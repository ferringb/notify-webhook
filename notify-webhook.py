#!/usr/bin/env python3

import dataclasses
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import typing
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import datetime

EMAIL_RE = re.compile(r"^(\"?)(?P<name>.*)\1\s+<(?P<email>.*)>$")

# see git-diff-tree 'RAW OUTPUT FORMAT'
# https://git-scm.com/docs/git-diff-tree#_raw_output_format
DIFF_TREE_RE = re.compile(
    r" \
        ^: \
          (?P<src_mode>[0-9]{6}) \
          \s+ \
          (?P<dst_mode>[0-9]{6}) \
          \s+ \
          (?P<src_hash>[0-9a-f]{7,40}) \
          \s+ \
          (?P<dst_hash>[0-9a-f]{7,40}) \
          \s+ \
          (?P<status>[ADTUX]|[CR][0-9]{1,3}|M[0-9]{0,3}) \
          \s+ \
          (?P<file1>\S+) \
          (?:\s+ \
            (?P<file2>\S+) \
          )? \
        $",
    re.MULTILINE | re.VERBOSE,
)

EMPTY_TREE_HASH = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZEROS = "0000000000000000000000000000000000000000"


def git(args):
    args = ["git"] + args
    cmd = subprocess.Popen(args, stdout=subprocess.PIPE)
    details = cmd.stdout.read()
    details = details.decode("utf-8", "replace").strip()
    return details


def _git_config():
    raw_config = git(["config", "-l", "-z"])
    items = raw_config.split("\0")
    # remove empty items
    items = filter(lambda i: len(i) > 0, items)
    # split into key/value based on FIRST \n; allow embedded \n in values
    items = [item.partition("\n")[0:3:2] for item in items]
    return OrderedDict(items)


GIT_CONFIG = _git_config()


def get_config(key, default=None):
    return GIT_CONFIG.get(key, default)


def get_repo_name():
    if get_config("core.bare", "false") == "true":
        name = os.path.basename(os.getcwd())
        if name.endswith(".git"):
            name = name[:-4]
        return name

    # Fallback:
    return os.path.basename(os.getcwd())


def get_repo_description():
    description = get_config("meta.description")
    if description:
        return description

    description = get_config("gitweb.description")
    if description:
        return description

    if os.path.exists("description"):
        with open("description", "r") as fp:
            return fp.read()

    return ""


def extract_name_email(s):
    p = EMAIL_RE
    _ = p.search(s.strip())
    if not _:
        return (None, None)
    name = (_.group("name") or "").strip()
    email = (_.group("email") or "").strip()
    return (name, email)


def get_repo_owner():
    # Explicit keys
    repo_owner_name = get_config("meta.ownername")
    repo_owner_email = get_config("meta.owneremail")
    # Fallback to gitweb
    gitweb_owner = get_config("gitweb.owner")
    if (
        gitweb_owner is not None
        and repo_owner_name is None
        and repo_owner_email is None
    ):
        (name, email) = extract_name_email(gitweb_owner)
        if name is not None:
            repo_owner_name = name
        if email is not None:
            repo_owner_email = email
    # Fallback to the repo
    if repo_owner_name is None or repo_owner_email is None:
        # You cannot include -n1 because it is processed before --reverse
        logmsg = git(["log", "--reverse", "--format=%an%x09%ae"]).split("\n")[0]
        # These will never be null
        (name, email) = logmsg.split("\t")
        if repo_owner_name is None:
            repo_owner_name = name
        if repo_owner_email is None:
            repo_owner_email = email

    return (repo_owner_name, repo_owner_email)


POST_URLS = get_config("hooks.webhookurl", "").strip().split()
# comma delimited format.  Tolerate dangling commas.
POST_URLS.extend(
    x.strip() for x in get_config("hooks.webhookurls", "").split(",") if x.strip()
)
POST_USER = get_config("hooks.authuser")
POST_PASS = get_config("hooks.authpass")
POST_REALM = get_config("hooks.authrealm")
POST_SECRET_TOKEN = get_config("hooks.secrettoken")
POST_CONTENTTYPE = get_config(
    "hooks.webhook-contenttype", "application/x-www-form-urlencoded"
)
POST_TIMEOUT = get_config("hooks.timeout")
DEBUG = get_config("hooks.webhook-debug")
REPO_URL = get_config("meta.url")
COMMIT_URL = get_config("meta.commiturl")
COMPARE_URL = get_config("meta.compareurl")
if COMMIT_URL is None and REPO_URL is not None:
    COMMIT_URL = REPO_URL + r"/commit/%s"
if COMPARE_URL is None and REPO_URL is not None:
    COMPARE_URL = REPO_URL + r"/compare/%s..%s"
REPO_NAME = get_repo_name()
REPO_DESC = get_repo_description()
(REPO_OWNER_NAME, REPO_OWNER_EMAIL) = get_repo_owner()


def get_revisions(
    old, new, commit_url: None | str = None
) -> typing.Iterable["CommitData"]:
    if old == new:
        # oh get bent.  Someone tried pushing a freshly init'd repo.
        # Not sure if it's possible in the real world, but account for it.
        return

    revs = git(["rev-list", "--pretty=medium", "--reverse", f"{old}..{new}"])
    sections = revs.split("\n\n")

    s = 0
    while s < len(sections):
        lines = sections[s].split("\n")

        # first line is 'commit HASH\n'
        sha = lines[0].strip().split(" ")[1]

        props = {
            "sha": sha,
            "added": [],
            "removed": [],
            "modified": [],
            "url": commit_url % sha if commit_url else None,
        }

        # call git diff-tree and get the file changes
        output = git(["diff-tree", "-r", "-C", "%s" % props["sha"]])

        # sort the changes into the added/modified/removed lists
        for i in DIFF_TREE_RE.finditer(output):
            item = i.groupdict()
            if item["status"] == "A":
                # addition of a file
                props["added"].append(item["file1"])
            elif item["status"][0] == "C":
                # copy of a file into a new one
                props["added"].append(item["file2"])
            elif item["status"] == "D":
                # deletion of a file
                props["removed"].append(item["file1"])
            elif item["status"] == "M":
                # modification of the contents or mode of a file
                props["modified"].append(item["file1"])
            elif item["status"][0] == "R":
                # renaming of a file
                props["removed"].append(item["file1"])
                props["added"].append(item["file2"])
            elif item["status"] == "T":
                # change in the type of the file
                props["modified"].append(item["file1"])
            else:
                # Covers U (file is unmerged)
                # and X ("unknown" change type, usually an error)
                # When we get X, we do not know what actually happened so
                # it's safest just to ignore it. We shouldn't be seeing U
                # anyway, so we can ignore that too.
                pass

        # read the header
        for l in lines[1:]:
            key, val = l.split(" ", 1)
            props[key[:-1].lower()] = val.strip()

        # read the commit message
        # Strip leading tabs/4-spaces on the message
        props["message"] = re.sub(
            r"^(\t| {4})", "", sections[s + 1], count=0, flags=re.MULTILINE
        )

        # use github time format
        basetime = datetime.strptime(props["date"][:-6], "%a %b %d %H:%M:%S %Y")
        tzstr = props["date"][-5:]
        props["date"] = basetime.strftime("%Y-%m-%dT%H:%M:%S") + tzstr

        m = EMAIL_RE.match(props["author"])
        if m:
            props["author"] = AuthorData(name=m.group(1), email=m.group(2))
        else:
            props["author"] = AuthorData(name="unknown", email="unkown")

        yield CommitData(**props)
        s += 2


def get_base_ref(commit, ref):
    branches = git(["branch", "--contains", commit]).split("\n")
    CURR_BRANCH_RE = re.compile(r"^\* \w+$")
    curr_branch = None

    if len(branches) > 1:
        on_master = False
        for branch in branches:
            if CURR_BRANCH_RE.match(branch):
                curr_branch = branch.strip("* \n")
            elif branch.strip() == "master":
                on_master = True

        if curr_branch is None and on_master:
            curr_branch = "master"

    if curr_branch is None:
        curr_branch = branches[0].strip("* \n")

    base_ref = "refs/heads/%s" % curr_branch

    if base_ref == ref:
        return None

    # Fallback
    return base_ref


# http://stackoverflow.com/a/20559031


def purify(obj):
    if hasattr(obj, "items"):
        newobj = type(obj)()
        for k in obj:
            if k is not None and obj[k] is not None:
                newobj[k] = purify(obj[k])
    elif hasattr(obj, "__iter__"):
        newobj = []
        for k in obj:
            if k is not None:
                newobj.append(purify(k))
    else:
        return obj
    return type(obj)(newobj)


class ToDict:
    def as_dict(self):
        d = dataclasses.asdict(self)  # pyright: ignore[reportArgumentType]
        d.update((k, v.as_dict()) for k, v in d.items() if isinstance(v, ToDict))
        return d


# use dataclasses to force the necessary shape of events.
# See https://web.archive.org/web/20201113233708/https://developer.github.com/webhooks/event-payloads/#push ;
# the original code was written against v3, github moved on and is marking a fair amount more as required.
# Continue what this code was originally written against, but also add things missing from that event spec.


@dataclasses.dataclass(kw_only=True)
class AuthorData(ToDict):
    name: str
    email: str


@dataclasses.dataclass(kw_only=True)
class _BaseCommitData(ToDict):
    # This is the basic definition.  Dataclass compiles and __init__ on the fly,
    # we split the classes to allow that to be reused.
    sha: str
    message: str
    author: AuthorData
    added: list[str]
    removed: list[str]
    modified: list[str]

    # outside spec from above.
    date: str
    url: None | str


class CommitData(_BaseCommitData):
    # This gets directly injected into the resultant dict.  It's secondary to allow
    # everything above to have runtime type validation.
    extras: dict[str, typing.Any]

    def __init__(self, **kwargs) -> None:
        # dataclasses don't allow extra params; we want the type validation, thus
        # we isolate what we allow dataclass to handle
        extras = kwargs.pop("extras", {})
        extras.update(
            {
                k: kwargs.pop(k)
                for k in list(kwargs)
                if k not in self.__dataclass_fields__
            }
        )
        super().__init__(**kwargs)
        self.extras = extras

    def as_dict(self):
        d = super().as_dict()
        # we've been returning this historically, so do so.
        d["id"] = self.sha
        d.update(self.extras)
        return d


@dataclasses.dataclass(kw_only=True)
class PushEvent(ToDict):
    ref: str
    before: str
    after: str
    repository: dict[str, str | dict]
    commits: list[CommitData]
    base_ref: None | str = None
    compare: None | str = None
    deleted: bool = False
    created: bool = False

    def as_dict(self):
        d = super().as_dict()
        d["head_commit"] = (
            None if self.deleted or not self.commits else d["commits"][-1]
        )
        # This is outside the spec above, but we've been returning it, so continue to do so.
        d["size"] = len(self.commits)
        return d


def make_json(old, new, ref, **json_serialize_kwargs):
    # Lots more fields could be added
    # https://developer.github.com/v3/activity/events/types/#pushevent

    deleted = new == ZEROS
    # This is the real sha of old, used for compare urls and for internal git calls.
    old_sha = EMPTY_TREE_HASH if old == ZEROS else old
    data = {
        "before": old,
        "after": new,
        "ref": ref,
        "deleted": deleted,
        "created": not deleted and old == ZEROS,
        # impossible to compare for a delete, so don't give the compare.
        "compare": (
            COMPARE_URL % (old_sha, new) if (COMPARE_URL and not deleted) else None
        ),
        "repository": {
            "url": REPO_URL,
            "name": REPO_NAME,
            "description": REPO_DESC,
            "owner": {"name": REPO_OWNER_NAME, "email": REPO_OWNER_EMAIL},
        },
        "commits": [],
        "base_ref": None,
    }

    if not deleted:
        data["commits"] = list(get_revisions(old_sha, new, COMMIT_URL))

        if base_ref := get_base_ref(new, ref):
            data["base_ref"] = base_ref

    # validate it fully.
    event = PushEvent(**data)

    return json.dumps(event.as_dict(), **json_serialize_kwargs)


def post_encode_data(contenttype, rawdata):
    if contenttype == "application/json":
        return rawdata.encode("UTF-8")
    if contenttype == "application/x-www-form-urlencoded":
        return urllib.parse.urlencode({"payload": rawdata}).encode("UTF-8")

    assert False, "Unsupported data encoding"
    return None


def build_handler(realm, url, user, passwd):
    # Default handler
    # HTTP requires a username at LEAST
    if not user:
        return urllib.request.HTTPHandler

    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(realm, url, user, passwd)
    handlerfunc = urllib.request.HTTPBasicAuthHandler
    if realm:
        handlerfunc = urllib.request.HTTPDigestAuthHandler
    return handlerfunc(password_mgr)


def post(url, data):
    headers = {
        "Content-Type": POST_CONTENTTYPE,
        "X-GitHub-Event": "push",
    }
    postdata = post_encode_data(POST_CONTENTTYPE, data)

    if POST_SECRET_TOKEN is not None:
        hmacobj = hmac.new(POST_SECRET_TOKEN, postdata, hashlib.sha1)
        signature = "sha1=" + hmacobj.hexdigest()
        headers["X-Hub-Signature"] = signature

    request = urllib.request.Request(url, postdata, headers)
    handler = build_handler(POST_USER, url, POST_PASS, POST_REALM)
    opener = urllib.request.build_opener(handler)

    try:
        if POST_TIMEOUT is not None:
            u = opener.open(request, None, float(POST_TIMEOUT))
        else:
            u = opener.open(request)
        u.read()
        u.close()
    except urllib.error.HTTPError as error:
        errmsg = "POST to %s returned error code %s." % (url, str(error.code))
        print(errmsg, file=sys.stderr)


def main(cli_args=sys.argv[1:], stdin=sys.stdin):
    # disable posting for local invocations.
    post_urls = POST_URLS
    debug = DEBUG
    if cli_args:
        debug = True
        post_urls = []
        if len(cli_args) % 3:
            raise Exception("cli args must be in groups of 3; old new ref")

        # make it simpler for cli invocation to behave like hook mode, without
        # making the humanhave to do things exactly the same.
        def f(val):
            if not val.strip("0"):
                return ZEROS
            # force full sha like hook does
            return git(["rev-parse", val])

        i = iter(cli_args)
        targets = zip(map(f, i), map(f, i), i)
    else:
        targets = (line.strip().split(" ", 2) for line in stdin)  # pyright: ignore[reportAssignmentType]

    for old, new, ref in targets:
        json_data = make_json(old, new, ref, indent=2 if debug else None)
        if debug:
            print(json_data)

        for url in post_urls:
            post(url, json_data)


if __name__ == "__main__":
    main()
