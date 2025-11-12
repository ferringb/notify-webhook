#!/usr/bin/env python3

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import typing
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from multiprocessing.pool import ThreadPool

EMPTY_TREE_HASH = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZEROS = "0000000000000000000000000000000000000000"


def git(args):
    args = ["git"] + args
    result = subprocess.run(
        args, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, check=True
    )
    return result.stdout.decode("utf-8", "replace").strip()


def _git_config() -> OrderedDict[str, str]:
    # drop the trailing record termination.  -z returns {key}\n{value} and just {key} if no value.
    # Ignore things without set values, including empty values.
    items = (x.split("\n", 1) for x in git(["config", "-l", "-z"]).split("\0")[:-1])
    return OrderedDict(x for x in items if len(x) != 1 and x[1])


GIT_CONFIG = _git_config()


T = typing.TypeVar("T")


def get_config(key, default: T = None) -> T | str:
    return GIT_CONFIG.get(key, default)  # pyright: ignore[reportReturnType]


def get_repo_name():
    if get_config("core.bare", "false") == "true":
        name = os.path.basename(os.getcwd())
        if name.endswith(".git"):
            name = name[:-4]
        return name

    # Fallback:
    return os.path.basename(os.getcwd())


def get_repo_description():
    if description := get_config("meta.description"):
        return description

    if description := get_config("gitweb.description"):
        return description

    if os.path.exists("description"):
        with open("description", "r") as fp:
            return fp.read().strip()

    return ""


_STRIP_QUOTED_NAME_RE = re.compile(r"^\s*([\"'])\s*(?P<value>.*?)\s*\1\s*$")


def _strip_quoted_name(val):
    # I can't think of why it would come through with \' beyond presumably git CLI escaping, but
    # whatever, cover that base too.
    if m := _STRIP_QUOTED_NAME_RE.match(val):
        return m.groupdict()["value"]
    return val


_EMAIL_RE = re.compile(r"\s*(?P<name>[^<]+?)\s*<\s*(?P<email>[^>]+?)\s*>\s*$")


def extract_name_email(s, default_missing=""):
    s = s.strip()

    if m := _EMAIL_RE.match(s):
        g = m.groupdict()
        # compatability: strip out quotation, since the original code tried to do this.

        return (_strip_quoted_name(g["name"]), g["email"])
    # guess a bit
    if "@" in s:
        return default_missing, s
    return (_strip_quoted_name(s) if s else default_missing, default_missing)


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
POST_PARALLELISM = int(get_config("hooks.post-parallelism", "2"))
POST_TIMEOUT = get_config("hooks.timeout")
# 2048 is github's current limit, so use that as a default.  0 disables the limit.
POST_MAX_COMMITS = int(get_config("hooks.post-max-commits", "2048"))
DEBUG = get_config("hooks.webhook-debug", "false") == "true"
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
    old, new, commit_url: None | str = None, max_commits: int = 0
) -> typing.Iterable["CommitData"]:
    if old == new:
        # oh get bent.  Someone tried pushing a freshly init'd repo.
        # Not sure if it's possible in the real world, but account for it.
        return

    def _split_trailers(data: str):
        results = []
        for trailer in data.split("\n"):
            # disregard valueless trailers
            if len(pairs := trailer.split("\t", 1)) == 2:
                results.append({pairs[0].strip(): pairs[1].strip()})
        return tuple(results)

    def empty_to_none(val):
        return val if val else None

    # see https://git-scm.com/docs/pretty-formats#_pretty_formats
    tformat_fields = OrderedDict(
        {
            # the strip works around some git pretty weirdness with trailers
            "sha": ("%H", str.strip),
            "_author.name": ("%an", empty_to_none),
            "_author.email": ("%ae", empty_to_none),
            "_committer.name": ("%cn", empty_to_none),
            "_committer.email": ("%ce", empty_to_none),
            "date": ("%ad", str),  # github uses ISO-8601
            "parents": ("%P", str.split),
            "message": ("%B", str.strip),
            "trailers": (
                # newline seperator, value seperator of tabs
                "%(trailers:separator=%x0a,only=true,unfold=true,key_value_separator=%x09)",
                _split_trailers,
            ),
        }
    )

    tformat = "%x00".join(x[0] for x in tformat_fields.values())
    tformat += "%x00"

    cmd = [
        "rev-list",
        "--date=iso-strict",
        "--no-commit-header",
        f"--pretty=tformat:{tformat}",
        "--reverse",
        f"{old}..{new}",
    ]
    if max_commits:
        cmd.append(f"--max-count={max_commits}")
    # drop the trailing terminator
    i = iter(git(cmd).split("\0")[:-1])

    for record_data in zip(*[i] * len(tformat_fields)):
        props = {}
        for pretty_field, value in zip(tformat_fields.items(), record_data):
            props[pretty_field[0]] = pretty_field[1][1](value)
        props["url"] = commit_url % props["sha"] if commit_url else None

        # fixup author and commiter
        for x in ("author", "committer"):
            props[x] = AuthorData(
                name=props.pop(empty_to_none(f"_{x}.name")),  # pyright: ignore[reportArgumentType]
                email=props.pop(empty_to_none(f"_{x}.email")),  # pyright: ignore[reportArgumentType]
            )
        assert not any(key.startswith("_") for key in props), (
            f"code issue; unprocessed keys came through: {list(props)}"
        )

        props.update(
            get_tree_changes_from_commit(
                props["sha"],
                # diff-tree doesn't report properly for the first commit in history;
                # force the parent if it's the first.
                forced_parent=EMPTY_TREE_HASH if not props["parents"] else None,
            )
        )

        yield CommitData(**props)


def get_tree_changes_from_commit(
    sha: str, forced_parent: str | None = None
) -> typing.Mapping[str, list[str]]:
    raw_tree = git(
        [
            "diff-tree",
            "--raw",
            "-z",
            "-r",
            # detect copies and renames
            "-C",
            "-M",
            "--no-commit-id",
            # force the simple format used below.
            "--name-status",
            sha if not forced_parent else f"{forced_parent}..{sha}",
            # ensure git knows that was a revish, flushing out any code bugs.
            "--",
        ]
    )
    # see git-diff-tree 'RAW OUTPUT FORMAT' for the actions involved
    # https://git-scm.com/docs/git-diff-tree#_raw_output_format

    # the last record still has a null which would trigger another record
    # parsing loop
    chunks = iter(raw_tree.split("\0")[:-1])

    changes = dict(added=[], removed=[], modified=[])
    for action in chunks:
        # actions can carry a confidence integer percent, thus strip it.
        action = action[0]
        match action:
            case "A":
                changes["added"].append(next(chunks))
            case "C":
                # copy.  Just record the addition
                next(chunks)  # discard source file
                changes["added"].append(next(chunks))
            case "D":
                changes["removed"].append(next(chunks))
            case "M":
                changes["modified"].append(next(chunks))
            case "R":
                changes["removed"].append(next(chunks))
                changes["added"].append(next(chunks))
            case "T":
                # change of type of file.  Symlink replacing a file, file replacing a symlink, etc.
                changes["added"].append(next(chunks))
            case "U":
                logging.warning(
                    "encountured U status in diff-tree; this impossible, there is a bug in this script"
                )
            case "X":
                logging.warning(
                    "encontured status X in diff-tree; please report this, it probably a bug in git itself"
                )
            case _:
                logging.warning(
                    f"unsupported action encountered during diff-tree: {action!r}"
                )
    return changes


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
class CommitData(ToDict):
    sha: str
    message: str
    author: AuthorData
    committer: AuthorData
    date: str
    added: list[str]
    removed: list[str]
    modified: list[str]
    parents: list[str]
    trailers: list[dict[str, str]]
    url: str | None


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
    forced: bool = False

    def as_dict(self):
        d = super().as_dict()
        d["head_commit"] = (
            None if self.deleted or not self.commits else d["commits"][-1]
        )
        # This is outside the spec above, but we've been returning it, so continue to do so.
        d["size"] = len(self.commits)
        return d


def make_json(old, new, ref, max_commits=POST_MAX_COMMITS, **json_serialize_kwargs):
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
        "forced": False,
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
        data["commits"] = list(
            get_revisions(old_sha, new, COMMIT_URL, max_commits=max_commits)
        )

        if base_ref := get_base_ref(new, ref):
            data["base_ref"] = base_ref
        if old_sha != EMPTY_TREE_HASH:
            try:
                git(["merge-base", "--is-ancestor", old_sha, new])
            except subprocess.CalledProcessError:
                data["forced"] = True

    # validate it fully.
    event = PushEvent(**data)

    return json.dumps(event.as_dict(), **json_serialize_kwargs)


def post_encode_data(contenttype, rawdata):
    match contenttype:
        case "application/json":
            return rawdata.encode("UTF-8")
        case "application/x-www-form-urlencoded":
            return urllib.parse.urlencode({"payload": rawdata}).encode("UTF-8")
        case _:
            raise Exception(f"Unsupported data encoding: {contenttype!r}")


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
        u = opener.open(request, timeout=float(POST_TIMEOUT) if POST_TIMEOUT else None)
        u.read()
        u.close()
    except urllib.error.HTTPError as error:
        logging.warning("POST to %s returned error code %s." % (url, str(error.code)))


def main(cli_args=sys.argv[1:], stdin=sys.stdin):
    # disable posting for local invocations.
    post_urls = POST_URLS
    pretty_print = DEBUG
    if cli_args:
        pretty_print = True
        post_urls = []
        if len(cli_args) % 3:
            raise Exception("cli args must be in groups of 3; old new ref")

        # make it simpler for cli invocation to behave like hook mode, without
        # making the human have to do things exactly the same.
        def f(val):
            if not val.strip("0"):
                return ZEROS
            # force full sha like hook does
            return git(["rev-parse", val])

        i = iter(cli_args)
        targets = zip(map(f, i), map(f, i), i)
    elif not post_urls and not DEBUG:
        # nothing to notify and the hook isn't being tested on a server... bail.
        return
    else:
        targets = (line.strip().split(" ", 2) for line in stdin)  # pyright: ignore[reportAssignmentType]

    failures = []
    with ThreadPool(max(1, min(POST_PARALLELISM, len(post_urls)))) as pool:
        for old, new, ref in targets:
            json_data = make_json(old, new, ref, indent=2 if pretty_print else None)
            if pretty_print:
                print(json_data)

            for url in post_urls:
                pool.apply_async(post, (url, json_data), error_callback=failures.append)

    return not failures


if __name__ == "__main__":
    import sys

    sys.exit(0 if main() else 1)
