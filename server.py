#!/usr/bin/env python3
"""Repo Activity - local desktop tool showing per-user activity (pushes, PR reviews)
for a Git repository hosted on Azure DevOps Server / TFS.

Runs a small HTTP server on 127.0.0.1 and opens the UI in the default browser.
HTTP calls go through curl so the macOS keychain CA trust and NTLM work out of the box.
Only the Python 3.9 standard library is used (works with /usr/bin/python3).
"""
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("REPO_ACTIVITY_PORT", "8765"))
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.expanduser("~/.config/repo-activity")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
KEYCHAIN_SERVICE = "repo-activity-tfs"
KEYCHAIN_ACCOUNT = "pat"
API_VERSION = "5.0"
APP_VERSION = "9"  # bump with index.html APP_VERSION; the page warns when they differ
IDLE_EXIT_SECONDS = 15 * 60
THREAD_WORKERS = 8

DEFAULTS = {
    "repoUrl": "",
    "auth": "pat",  # "pat" | "git"
    "days": 60,
    "deep": True,
    "localRepo": "",   # local clone used for AI reviews; auto-detected when empty
    "claudePath": "",  # claude CLI; auto-detected when empty
    "reviewModel": "",  # --model for AI reviews; empty = the CLI's own default
}
CACHE_DIR = os.path.expanduser("~/.cache/repo-activity")

VOTE_LABELS = {10: "Approved", 5: "Approved with suggestions", 0: "No vote",
               -5: "Waiting for author", -10: "Rejected"}


# ---------------------------------------------------------------- config / secrets

def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({k: cfg[k] for k in DEFAULTS}, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def keychain_get():
    r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE,
                        "-a", KEYCHAIN_ACCOUNT, "-w"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def keychain_set(secret):
    if not re.fullmatch(r"[A-Za-z0-9]{20,100}", secret):
        raise ValueError("That doesn't look like a PAT (expected 20-100 letters/digits).")
    # Fed through `security -i` on stdin so the token never shows up in the process list.
    r = subprocess.run(["security", "-i"], capture_output=True, text=True,
                       input="add-generic-password -U -s %s -a %s -w %s\n"
                             % (KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, secret))
    if r.returncode != 0 or keychain_get() != secret:
        raise ValueError("Could not save the PAT to the keychain: " + (r.stderr or r.stdout).strip())


def keychain_delete():
    subprocess.run(["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE,
                    "-a", KEYCHAIN_ACCOUNT], capture_output=True)


_git_creds = {}


def git_credentials(host):
    if host not in _git_creds:
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
        r = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=%s\n\n" % host,
                           capture_output=True, text=True, env=env, timeout=30)
        fields = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
        if r.returncode != 0 or not fields.get("password"):
            raise ApiError("No git credential stored for %s. Use a PAT instead." % host, 401)
        _git_creds[host] = (fields.get("username", ""), fields["password"])
    return _git_creds[host]


# ---------------------------------------------------------------- Azure DevOps client

class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def parse_repo_url(url):
    """https://host/<collection>/<project>/_git/<repo>[/...] -> parts."""
    u = urllib.parse.urlsplit(url.strip())
    parts = [urllib.parse.unquote(p) for p in u.path.split("/") if p]
    if not u.scheme or not u.netloc or "_git" not in parts:
        raise ApiError("Expected a repository URL like https://host/Collection/Project/_git/repo", 400)
    i = parts.index("_git")
    if i < 2 or i + 1 >= len(parts):
        raise ApiError("Expected a repository URL like https://host/Collection/Project/_git/repo", 400)
    collection = "/".join(urllib.parse.quote(p) for p in parts[:i - 1])
    base = "%s://%s/%s" % (u.scheme, u.netloc, collection)
    project, repo = parts[i - 1], parts[i + 1]
    return {
        "base": base, "project": project, "repo": repo, "host": u.hostname,
        "webRepo": "%s/%s/_git/%s" % (base, urllib.parse.quote(project), urllib.parse.quote(repo)),
    }


def _curl_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Client:
    def __init__(self, cfg):
        self.loc = parse_repo_url(cfg["repoUrl"])
        if cfg.get("auth") == "git":
            self.user, self.password = git_credentials(self.loc["host"])
            self.auth_flag = "--anyauth"  # lets curl negotiate NTLM/Negotiate/Basic
        else:
            pat = keychain_get()
            if not pat:
                raise ApiError("No Personal Access Token saved yet. Open Settings and add one.", 401)
            self.user, self.password = "", pat
            self.auth_flag = "--basic"

    def _get(self, url, params):
        return self._request(url, params)

    def _request(self, url, params, payload=None):
        params = dict(params or {})
        params["api-version"] = API_VERSION
        full = url + "?" + urllib.parse.urlencode(params, safe="$")
        conf = "user = %s\nurl = %s\n" % (_curl_quote(self.user + ":" + self.password), _curl_quote(full))
        cmd = ["curl", "-sS", "--compressed", "--max-time", "120",
               "-H", "Accept: application/json", self.auth_flag,
               "-w", "\n__HTTP_STATUS__%{http_code}", "-K", "-"]
        if payload is None:
            cmd[3:3] = ["--retry", "2"]  # never retry writes: a retry could post twice
        else:
            conf += 'request = "POST"\nheader = "Content-Type: application/json"\ndata-binary = %s\n' % _curl_quote(
                json.dumps(payload))
        try:
            r = subprocess.run(cmd, input=conf, capture_output=True, text=True, timeout=400)
        except subprocess.TimeoutExpired:
            raise ApiError("Request timed out: " + url)
        if r.returncode != 0:
            msg = r.stderr.strip() or "curl exit %d" % r.returncode
            if r.returncode in (6, 7, 28):
                msg += " (are you connected to the VPN?)"
            raise ApiError(msg)
        body, _, status = r.stdout.rpartition("\n__HTTP_STATUS__")
        status = int(status or 0)
        if status in (401, 403):
            scope = "Code (Read & write)" if payload is not None else "Code (Read)"
            raise ApiError("Authentication failed (HTTP %d). Check the PAT / credentials and its %s scope."
                           % (status, scope), status)
        try:
            data = json.loads(body) if body.strip() else {}
        except ValueError:
            if status in (200, 203):  # TFS serves a sign-in HTML page for bad tokens
                raise ApiError("Server returned a sign-in page instead of data. The PAT is probably invalid or expired.", 401)
            raise ApiError("HTTP %d from %s" % (status, url), status)
        if status >= 400:
            raise ApiError(data.get("message") or "HTTP %d" % status, status)
        return data

    def project_api(self, path, params=None):
        return self._get("%s/%s/_apis/%s" % (self.loc["base"], urllib.parse.quote(self.loc["project"]), path), params)

    def collection_api(self, path, params=None):
        return self._get("%s/_apis/%s" % (self.loc["base"], path), params)

    def repo_api(self, path, params=None):
        suffix = "/" + path if path else ""
        return self.project_api("git/repositories/%s%s" % (urllib.parse.quote(self.loc["repo"]), suffix), params)

    def repo_post(self, path, body):
        url = "%s/%s/_apis/git/repositories/%s/%s" % (self.loc["base"], urllib.parse.quote(self.loc["project"]),
                                                     urllib.parse.quote(self.loc["repo"]), path)
        return self._request(url, None, body)

    def pr_web_url(self, pr_id):
        return "%s/pullrequest/%s" % (self.loc["webRepo"], pr_id)


# ---------------------------------------------------------------- helpers

def norm_date(s):
    """ADO timestamps ('2026-09-20T10:11:12.1234567Z') -> '2026-09-20T10:11:12Z' (sortable as strings)."""
    return s[:19] + "Z" if s and len(s) >= 19 else None


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def max_date(*values):
    vals = [v for v in values if v]
    return max(vals) if vals else None


def prop(props, name):
    v = (props or {}).get(name)
    return v.get("$value") if isinstance(v, dict) else v


def is_service_identity(name, unique):
    n, un = (name or "").lower(), (unique or "").lower()
    # Built-in TFS accounts such as Microsoft.TeamFoundation.System / Microsoft.VisualStudio.Services.TFS
    system = any(s in n or s in un for s in ("microsoft.teamfoundation", "microsoft.visualstudio"))
    return system or "build service" in n or n.startswith("[") or un.startswith("vstfs:")


# ---------------------------------------------------------------- scan

class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex[:12]
        self.stage = "Starting"
        self.done = 0
        self.total = 0
        self.error = None
        self.result = None
        self.finished = False

    def to_json(self):
        return {"id": self.id, "stage": self.stage, "done": self.done, "total": self.total,
                "error": self.error, "finished": self.finished, "result": self.result}


JOBS = {}


def paged(fetch, top, on_page):
    skip = 0
    while True:
        vals = fetch(top, skip).get("value", [])
        if on_page(vals) is False or len(vals) < top:
            return
        skip += top


def run_scan(job, cfg):
    try:
        job.result = scan(job, cfg)
    except ApiError as e:
        job.error = str(e)
    except Exception as e:  # surface anything unexpected in the UI
        job.error = "%s: %s" % (type(e).__name__, e)
    finally:
        job.finished = True


def scan(job, cfg):
    c = Client(cfg)
    days = max(1, int(cfg.get("days", 60)))
    deep = bool(cfg.get("deep", True))
    now = dt.datetime.utcnow()
    since = iso(now - dt.timedelta(days=days))
    cutoff = iso(now - dt.timedelta(days=days + 30))

    users = {}

    def user(idn):
        uid = idn.get("id") or idn.get("uniqueName") or idn.get("displayName")
        u = users.get(uid)
        if u is None:
            u = users[uid] = {
                "id": uid, "name": idn.get("displayName") or idn.get("uniqueName") or "Unknown",
                "unique": idn.get("uniqueName") or "", "pushes": [], "created": [],
                "reviews": {}, "comments": 0, "lastComment": None, "pending": [],
            }
        return u

    # 1. pushes in window
    job.stage = "Fetching pushes"
    pushes_total = [0]

    def on_pushes(vals):
        for p in vals:
            refs = [r.get("name", "").replace("refs/heads/", "") for r in p.get("refUpdates") or []]
            user(p.get("pushedBy") or {})["pushes"].append(
                {"date": norm_date(p.get("date")), "refs": refs, "id": p.get("pushId")})
        pushes_total[0] += len(vals)
        job.stage = "Fetching pushes (%d)" % pushes_total[0]

    paged(lambda top, skip: c.repo_api("pushes", {
        "searchCriteria.fromDate": since, "searchCriteria.includeRefUpdates": "true",
        "$top": top, "$skip": skip}), 500, on_pushes)

    # 2. pull requests touching the window (+ every active PR, reviews on old PRs still count)
    job.stage = "Fetching pull requests"
    prs = {}

    def keep_pr(pr):
        prs[pr["pullRequestId"]] = pr

    def on_all_prs(vals):
        oldest = None
        for pr in vals:
            created, closed = norm_date(pr.get("creationDate")), norm_date(pr.get("closedDate"))
            oldest = min(oldest, created) if oldest and created else (oldest or created)
            if (created and created >= since) or (closed and closed >= since):
                keep_pr(pr)
        job.stage = "Fetching pull requests (%d)" % len(prs)
        return not (oldest and oldest < cutoff)

    paged(lambda top, skip: c.repo_api("pullrequests", {
        "searchCriteria.status": "all", "$top": top, "$skip": skip}), 200, on_all_prs)
    active_ids = set()

    def on_active(vals):
        for pr in vals:
            active_ids.add(pr["pullRequestId"])
            keep_pr(pr)

    paged(lambda top, skip: c.repo_api("pullrequests", {
        "searchCriteria.status": "active", "$top": top, "$skip": skip}), 200, on_active)

    pr_out = {}
    for pid, pr in prs.items():
        author = pr.get("createdBy") or {}
        created = norm_date(pr.get("creationDate"))
        pr_out[pid] = {
            "id": pid, "title": pr.get("title", ""), "status": pr.get("status"),
            "author": author.get("displayName", ""), "authorId": author.get("id"),
            "created": created, "closed": norm_date(pr.get("closedDate")),
            "target": (pr.get("targetRefName") or "").replace("refs/heads/", ""),
            "source": (pr.get("sourceRefName") or "").replace("refs/heads/", ""),
            "url": c.pr_web_url(pid),
        }
        if created and created >= since:
            user(author)["created"].append(pid)
        for r in pr.get("reviewers") or []:
            if r.get("isContainer") or r.get("id") == author.get("id"):
                continue
            if pr.get("status") == "active" and r.get("vote", 0) == 0:
                user(r)["pending"].append(pid)

    def add_review(u, pid, date, vote, approx, comments=0):
        rv = u["reviews"].get(pid)
        if rv is None:
            rv = u["reviews"][pid] = {"pr": pid, "date": date, "vote": vote, "approx": approx, "comments": 0}
        elif date and (not rv["date"] or date >= rv["date"]):
            rv["date"] = date
            if vote is not None:
                rv["vote"] = vote
        elif rv["vote"] is None and vote is not None:
            rv["vote"] = vote
        rv["comments"] += comments

    # 3. reviews
    if deep:
        job.stage = "Reading review threads"
        job.total = len(prs)
        job.done = 0

        def fetch_threads(pid):
            return pid, c.repo_api("pullRequests/%s/threads" % pid).get("value", [])

        with ThreadPoolExecutor(THREAD_WORKERS) as ex:
            futures = [ex.submit(fetch_threads, pid) for pid in prs]
            for fut in as_completed(futures):
                pid, threads = fut.result()
                job.done += 1
                author_id = pr_out[pid]["authorId"]
                for t in threads:
                    comments = t.get("comments") or []
                    if prop(t.get("properties"), "CodeReviewThreadType") == "VoteUpdate" and comments:
                        voter = comments[0].get("author") or {}
                        date = norm_date(t.get("publishedDate") or comments[0].get("publishedDate"))
                        if voter.get("id") == author_id or not date or date < since:
                            continue
                        try:
                            vote = int(prop(t.get("properties"), "CodeReviewVoteResult"))
                        except (TypeError, ValueError):
                            vote = None
                        add_review(user(voter), pid, date, vote, False)
                        continue
                    for cm in comments:
                        if cm.get("commentType") != "text" or cm.get("isDeleted"):
                            continue
                        date = norm_date(cm.get("publishedDate"))
                        who = cm.get("author") or {}
                        if not date or date < since or who.get("id") == author_id:
                            continue
                        u = user(who)
                        u["comments"] += 1
                        u["lastComment"] = max_date(u["lastComment"], date)
                        add_review(u, pid, date, None, False, comments=1)
    else:
        for pid, pr in prs.items():
            p = pr_out[pid]
            if not ((p["created"] and p["created"] >= since) or (p["closed"] and p["closed"] >= since)):
                continue
            for r in pr.get("reviewers") or []:
                if r.get("isContainer") or r.get("vote", 0) == 0 or r.get("id") == p["authorId"]:
                    continue
                add_review(user(r), pid, p["closed"] or p["created"], r.get("vote"), True)

    # 4. shape result
    job.stage = "Aggregating"
    out_users = []
    for u in users.values():
        if is_service_identity(u["name"], u["unique"]):
            continue
        pushes = sorted((p for p in u["pushes"] if p["date"]), key=lambda p: p["date"], reverse=True)
        reviews = sorted(u["reviews"].values(), key=lambda r: r["date"] or "", reverse=True)
        created = sorted(u["created"], key=lambda pid: pr_out[pid]["created"] or "", reverse=True)
        votes = [r["vote"] for r in reviews]
        last_push = pushes[0]["date"] if pushes else None
        last_review = reviews[0]["date"] if reviews else None
        last_created = pr_out[created[0]]["created"] if created else None
        out_users.append({
            "id": u["id"], "name": u["name"], "unique": u["unique"],
            "lastPush": last_push, "pushCount": len(pushes),
            "branches": len({r for p in pushes for r in p["refs"]}),
            "pushes": pushes[:300],
            "created": created, "createdCount": len(created),
            "reviews": reviews, "reviewCount": len(reviews),
            "approved": sum(1 for v in votes if v in (10, 5)),
            "waiting": sum(1 for v in votes if v == -5),
            "rejected": sum(1 for v in votes if v == -10),
            "comments": u["comments"], "lastReview": last_review,
            "pending": sorted(set(u["pending"]) & active_ids, reverse=True),
            "lastActivity": max_date(last_push, last_review, u["lastComment"], last_created),
        })
    out_users = [u for u in out_users if u["lastActivity"] or u["pending"]]
    out_users.sort(key=lambda u: u["lastActivity"] or "", reverse=True)

    return {
        "repo": {"project": c.loc["project"], "repo": c.loc["repo"], "web": c.loc["webRepo"]},
        "days": days, "deep": deep, "since": since, "generatedAt": iso(now),
        "totals": {
            "users": len(out_users), "pushes": pushes_total[0],
            "prsCreated": sum(1 for p in pr_out.values() if p["created"] and p["created"] >= since),
            "reviews": sum(u["reviewCount"] for u in out_users),
            "activePrs": len(active_ids),
        },
        "users": out_users, "prs": pr_out,
    }


# ---------------------------------------------------------------- single-user lookups

def lookup_identities(cfg, query):
    c = Client(cfg)
    data = c.collection_api("identities", {"searchFilter": "General", "filterValue": query,
                                           "queryMembership": "None"})
    out = []
    for i in data.get("value", []):
        props = i.get("properties") or {}
        name = i.get("customDisplayName") or i.get("providerDisplayName") or ""
        if i.get("isContainer") or is_service_identity(name, ""):
            continue
        out.append({"id": i.get("id"), "name": name,
                    "unique": prop(props, "Account") or prop(props, "Mail") or "",
                    "active": i.get("isActive", True)})
    return out[:20]


def user_detail(cfg, uid, days):
    """All-time last push plus PR activity for one identity (independent of the team scan)."""
    c = Client(cfg)
    since = iso(dt.datetime.utcnow() - dt.timedelta(days=days))
    last = c.repo_api("pushes", {"searchCriteria.pusherId": uid,
                                 "searchCriteria.includeRefUpdates": "true", "$top": 1}).get("value", [])
    reviewer_prs = c.repo_api("pullrequests", {"searchCriteria.reviewerId": uid,
                                               "searchCriteria.status": "all", "$top": 300}).get("value", [])
    creator_prs = c.repo_api("pullrequests", {"searchCriteria.creatorId": uid,
                                              "searchCriteria.status": "all", "$top": 100}).get("value", [])

    def pr_brief(pr, vote=None):
        return {"id": pr["pullRequestId"], "title": pr.get("title", ""), "status": pr.get("status"),
                "author": (pr.get("createdBy") or {}).get("displayName", ""),
                "created": norm_date(pr.get("creationDate")), "closed": norm_date(pr.get("closedDate")),
                "url": c.pr_web_url(pr["pullRequestId"]), "vote": vote}

    reviews, pending = [], []
    for pr in reviewer_prs:
        me = next((r for r in pr.get("reviewers") or [] if r.get("id") == uid), None)
        if not me or (pr.get("createdBy") or {}).get("id") == uid:
            continue
        b = pr_brief(pr, me.get("vote", 0))
        if pr.get("status") == "active" and b["vote"] == 0:
            pending.append(b)
        elif b["vote"] != 0 and max_date(b["created"], b["closed"]) >= since:
            reviews.append(b)
    created = [pr_brief(pr) for pr in creator_prs if (norm_date(pr.get("creationDate")) or "") >= since]
    lp = last[0] if last else None
    return {
        "lastPushAllTime": {"date": norm_date(lp.get("date")),
                            "refs": [r.get("name", "").replace("refs/heads/", "") for r in lp.get("refUpdates") or []]}
        if lp else None,
        "reviews": reviews, "pending": pending, "created": created, "since": since,
    }


# ---------------------------------------------------------------- active PRs + AI review

def repo_key(loc):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", "%s-%s" % (loc["project"], loc["repo"]))


def review_cache_path(loc, pr_id):
    return os.path.join(CACHE_DIR, "reviews", "%s-%s.json" % (repo_key(loc), pr_id))


def project_context_path(loc):
    return os.path.join(CACHE_DIR, "contexts", "%s.json" % repo_key(loc))


def load_review(loc, pr_id):
    try:
        with open(review_cache_path(loc, pr_id)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def list_active_prs(cfg):
    c = Client(cfg)
    out = []

    def on_page(vals):
        for pr in vals:
            author = pr.get("createdBy") or {}
            if is_service_identity(author.get("displayName"), author.get("uniqueName")):
                continue
            src_commit = (pr.get("lastMergeSourceCommit") or {}).get("commitId")
            cached = load_review(c.loc, pr["pullRequestId"])
            out.append({
                "id": pr["pullRequestId"], "title": pr.get("title", ""), "isDraft": bool(pr.get("isDraft")),
                "author": author.get("displayName", ""), "created": norm_date(pr.get("creationDate")),
                "source": (pr.get("sourceRefName") or "").replace("refs/heads/", ""),
                "target": (pr.get("targetRefName") or "").replace("refs/heads/", ""),
                "mergeStatus": pr.get("mergeStatus"), "url": c.pr_web_url(pr["pullRequestId"]),
                "reviewers": [{"name": r.get("displayName", ""), "vote": r.get("vote", 0),
                               "group": bool(r.get("isContainer")), "required": bool(r.get("isRequired"))}
                              for r in pr.get("reviewers") or []],
                "ai": None if not cached else {
                    "verdict": (cached.get("review") or {}).get("verdict"),
                    "findings": len((cached.get("review") or {}).get("findings") or []),
                    "outdated": bool(src_commit and cached.get("sourceCommit") != src_commit),
                    "incomplete": bool(cached.get("incomplete")),
                    "at": cached.get("at"),
                },
            })

    paged(lambda top, skip: c.repo_api("pullrequests", {
        "searchCriteria.status": "active", "$top": top, "$skip": skip}), 200, on_page)
    out.sort(key=lambda p: p["created"] or "", reverse=True)
    return out


def run_cmd(cmd, cwd=None, timeout=900):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    if r.returncode != 0:
        raise ApiError("%s failed: %s" % (" ".join(cmd[:4]), (r.stderr or r.stdout).strip()[-800:]))
    return r.stdout


def detect_local_repo(cfg):
    """Configured path, else a clone under ~ whose origin points at the configured repo."""
    loc = parse_repo_url(cfg["repoUrl"])
    if cfg.get("localRepo"):  # explicitly configured: trust it
        path = os.path.expanduser(cfg["localRepo"])
        if os.path.exists(os.path.join(path, ".git")):
            return path
        raise ApiError("Local clone %s is not a git repository." % path, 400)
    candidates = [
        os.path.expanduser("~/" + loc["repo"]), os.path.expanduser("~/StudioProjects/" + loc["repo"]),
        os.path.expanduser("~/AndroidStudioProjects/" + loc["repo"]), os.path.expanduser("~/projects/" + loc["repo"])]
    for path in candidates:
        path = os.path.expanduser(path or "")
        if not os.path.isdir(os.path.join(path, ".git")):
            continue
        try:
            origin = parse_repo_url(run_cmd(["git", "-C", path, "remote", "get-url", "origin"], timeout=10).strip())
        except ApiError:
            continue
        if origin["repo"].lower() == loc["repo"].lower() and origin["project"].lower() == loc["project"].lower():
            return path
    raise ApiError("No local clone of %s found. Set \"Local clone\" in Settings." % loc["repo"], 400)


def _version_key(path):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", path)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def detect_claude(cfg):
    if cfg.get("claudePath"):
        p = os.path.expanduser(cfg["claudePath"])
        if os.access(p, os.X_OK):
            return p
        raise ApiError("Claude CLI path %s is not executable." % p, 400)
    # Prefer the newest build: the VS Code extension's bundled CLI is usually newer than a stale ~/.local/bin one.
    found = []
    for p in [os.path.expanduser("~/.local/bin/claude"), "/opt/homebrew/bin/claude", "/usr/local/bin/claude",
              os.path.expanduser("~/.claude/local/claude")]:
        if os.access(p, os.X_OK):
            found.append((_version_key(os.path.realpath(p)), p))
    ext_root = os.path.expanduser("~/.vscode/extensions")
    for d in (os.listdir(ext_root) if os.path.isdir(ext_root) else []):
        p = os.path.join(ext_root, d, "resources", "native-binary", "claude")
        if d.startswith("anthropic.claude-code-") and os.access(p, os.X_OK):
            found.append((_version_key(d), p))
    if found:
        return max(found)[1]
    r = subprocess.run(["/bin/zsh", "-lc", "command -v claude"], capture_output=True, text=True, timeout=15)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    raise ApiError("Claude Code CLI not found. Install it or set its path in Settings.", 400)


REVIEW_MAX_FILES = 10
REVIEW_MAX_LINES = 900
REVIEW_MAX_TURNS = 20
REVIEW_SLICES_PER_RUN = 2

LOW_SIGNAL_EXTENSIONS = {
    ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".svg", ".webp",
    ".eot", ".otf", ".ttf", ".woff", ".woff2",
}
LOW_SIGNAL_NAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "podfile.lock",
    "cartfile.resolved", "gradle.lockfile",
}
HIGH_RISK_XML_NAMES = {
    "androidmanifest.xml", "network_security_config.xml", "backup_rules.xml",
    "data_extraction_rules.xml", "provider_paths.xml", "file_paths.xml",
    "shortcuts.xml", "authenticator.xml", "device_admin_receiver.xml",
}
GENERATED_PATH_PARTS = {"build", "dist", "generated", "node_modules", "vendor"}
FEATURE_PATH_MARKERS = {
    "feature", "features", "module", "modules", "package", "packages", "service", "services",
}
CONTEXT_MANIFEST_NAMES = {
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "libs.versions.toml", "package.json", "pyproject.toml",
    "requirements.txt", "pom.xml", "cargo.toml", "go.mod", "composer.json",
    "gemfile", "podfile", "makefile", "cmakelists.txt",
}
CONTEXT_EXACT_NAMES = {
    "claude.md", "contributing.md", "architecture.md", "security.md", "testing.md",
    ".editorconfig", ".eslintrc", ".eslintrc.json", ".prettierrc", "detekt.yml",
    "androidmanifest.xml", "proguard-rules.pro", "consumer-rules.pro", "lint.xml",
}
CONTEXT_TOOLS = "Read,Grep,Glob,Bash(git log:*),Bash(git show:*),Bash(git ls-tree:*)"


PROJECT_CONTEXT_PROMPT = """Analyze this repository once to create a compact, reusable context profile for future
code reviews. The checkout is the target branch before any pull request changes.

Start with these architecture, documentation, and build files:
{sources}

Use Read/Glob/Grep to inspect those files and a small number of representative production and test files. Record only
facts supported by the repository; do not invent standards. Keep the profile compact because it will be reused in
future review prompts. Do not review code changes and do not modify files.

This repository is primarily reviewed as an Android project. When present, capture the Gradle module graph and
dependency boundaries; UI approach (Compose, Views, or mixed); ViewModel/state/event conventions; coroutines,
dispatchers, Flow and lifecycle rules; dependency injection; navigation; networking and persistence layers; error
mapping; feature flags; analytics/privacy practices; and unit/instrumentation/screenshot test conventions.

End with ONE fenced ```json block and nothing after it:
{{"overview": "at most 3 sentences",
 "architecture": ["concise fact or dependency rule"],
 "conventions": ["review-relevant coding or error-handling rule"],
 "testing": ["test layout and expectations"],
 "security": ["project-specific privacy, authentication, or secrets rule"],
 "areas": [{{"name": "feature or subsystem", "paths": ["path prefix or glob"],
             "guidance": ["architecture facts and review risks specific to this area"]}}],
 "sources": ["repository files that support this profile"]}}

Use at most 12 items in each top-level list, 20 areas, and 6 guidance items per area.
"""


SLICE_REVIEW_PROMPT = """You are reviewing feature slice "{feature}" ({part} of {total}) from Azure DevOps pull
request !{id} "{title}" by {author}. Source branch `{source}` -> target `{target}`. The current directory is checked
out at the PR's source commit (HEAD), and `{base}` is the merge base with the target.

PR description:
{description}

Reusable project context (facts extracted from the target branch):
{project_context}

This slice is strictly limited to these files:
{files}

How to review:
- Review every semantic change in the listed files. Use `git diff {base}...HEAD -- <listed paths>` and open surrounding
  code with Read/Grep only when needed to verify a concrete problem.
- Do not inspect diffs for other PR files. You may read unchanged dependency or caller code only to verify a contract.
- Focus on correctness bugs, crashes/NPEs, coroutine/threading and lifecycle issues, leaks, security, broken error
  handling, API/contract breaks, persistence migrations, and risky logic without tests.
- For Android code, verify lifecycle-aware collection, dispatcher use, cancellation, Compose state stability and
  recomposition, ViewModel event handling, navigation arguments, process recreation, permissions, exported
  components, PendingIntent flags, persistence migrations, and main-thread I/O where relevant.
- Skip formatting and style nits a linter would catch. Verify every finding against the code; never speculate.
- Do not modify any files.

End your answer with ONE fenced ```json block and nothing after it, in exactly this shape:
{{"verdict": "approve" | "approve_with_suggestions" | "needs_work",
 "summary": "2-4 sentences on what the PR does and its overall quality",
 "findings": [{{"severity": "critical" | "major" | "minor" | "nit", "file": "path/relative/to/repo", "line": 123,
   "title": "short title", "detail": "why this is a problem, with a concrete failing scenario",
   "suggestion": "how to fix it (a code snippet is fine)"}}]}}
"""

REVIEW_TOOLS = "Read,Grep,Glob,Bash(git diff:*),Bash(git log:*),Bash(git show:*),Bash(git blame:*)"


def claude_cmd(claude, prompt, model, max_turns=30, allowed_tools=REVIEW_TOOLS):
    # The CLI runs inside the PR checkout, so never load hooks, MCP servers, skills, or permissions from it.
    cmd = [claude, "-p", prompt, "--output-format", "stream-json", "--verbose",
           "--setting-sources", "user", "--strict-mcp-config", "--disable-slash-commands",
           "--allowedTools", allowed_tools, "--disallowedTools", "Edit,Write,NotebookEdit,WebFetch,WebSearch",
           "--max-turns", str(max_turns)]
    if model:
        cmd += ["--model", model]
    return cmd


class ReviewJob:
    def __init__(self, pr_id):
        self.pr_id = pr_id
        self.stage = "Queued"
        self.log = []
        self.error = None
        self.result = None
        self.finished = False
        self.proc = None
        self.cancelled = False

    def note(self, line):
        self.log.append({"t": iso(dt.datetime.utcnow()), "m": line[:300]})
        del self.log[:-300]

    def to_json(self):
        return {"id": self.pr_id, "stage": self.stage, "log": self.log, "error": self.error,
                "finished": self.finished, "result": self.result}


REVIEW_JOBS = {}
REVIEW_LOCK = threading.Lock()  # one shared worktree -> one review at a time


def describe_tool(name, inp, root):
    inp = inp or {}
    target = str(inp.get("file_path") or inp.get("command") or inp.get("pattern") or inp.get("path") or "")
    target = target.replace(root + "/", "").replace(os.path.expanduser("~"), "~")
    return "%s %s" % (name, target)


def run_review(job, cfg, work=None):
    try:
        with REVIEW_LOCK:
            if job.cancelled:
                raise ApiError("Cancelled")
            (work or review)(job, cfg)
    except ApiError as e:
        job.error = str(e)
    except subprocess.TimeoutExpired:
        job.error = "Timed out"
    except Exception as e:
        job.error = "%s: %s" % (type(e).__name__, e)
    finally:
        job.proc = None
        job.finished = True


def review_worktree(loc):
    return os.path.join(CACHE_DIR, "worktrees", repo_key(loc))


def checkout_worktree(job, local, wt, commit):
    """Point the shared review worktree at `commit`, creating it on first use."""
    git = ["git", "-c", "core.hooksPath=/dev/null"]
    if not os.path.isdir(os.path.join(wt, ".git")) and not os.path.isfile(os.path.join(wt, ".git")):
        job.note("Creating review worktree (first time only, takes a minute)")
        os.makedirs(os.path.dirname(wt), exist_ok=True)
        run_cmd(["git", "-C", local, "worktree", "prune"])
        run_cmd(git + ["-C", local, "worktree", "add", "--detach", "--force", wt, commit], timeout=1800)
    else:
        run_cmd(git + ["-C", wt, "checkout", "--detach", "--force", "--quiet", commit], timeout=1800)
        run_cmd(["git", "-C", wt, "clean", "-fdq"])


def run_claude(job, claude, prompt, wt, model, resume=None, max_turns=30, allowed_tools=REVIEW_TOOLS):
    """Runs the read-only Claude CLI in `wt`, streaming progress into job.log.
    Returns (result_event, model_used, session_id)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_CODE_") and k != "CLAUDECODE"}
    env["PATH"] = os.pathsep.join([os.path.expanduser("~/.local/bin"), "/opt/homebrew/bin", "/usr/local/bin",
                                   env.get("PATH", "/usr/bin:/bin")])
    cmd = claude_cmd(claude, prompt, model, max_turns, allowed_tools)
    if resume:
        cmd += ["--resume", resume]
    job.proc = subprocess.Popen(cmd, cwd=wt, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
    killer = threading.Timer(30 * 60, job.proc.kill)
    killer.start()
    stderr_lines = []
    proc = job.proc
    threading.Thread(target=lambda: stderr_lines.extend(proc.stderr), daemon=True).start()
    final = None
    model_used = None
    session_id = None
    try:
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            session_id = ev.get("session_id") or session_id
            if ev.get("type") == "system" and ev.get("model"):
                model_used = ev["model"]
            elif ev.get("type") == "assistant":
                for item in (ev.get("message") or {}).get("content") or []:
                    if item.get("type") == "tool_use":
                        job.note(describe_tool(item.get("name", ""), item.get("input"), wt))
                    elif item.get("type") == "text" and item.get("text", "").strip():
                        job.note(item["text"].strip().splitlines()[0])
            elif ev.get("type") == "result":
                final = ev
        proc.wait()
    finally:
        killer.cancel()
    if job.cancelled:
        raise ApiError("Cancelled")
    if not final or final.get("is_error"):
        err = "".join(stderr_lines).strip()
        if proc.returncode in (-9, 137) and not final and not err:
            raise ApiError("macOS killed the Claude CLI (%s) the moment it started (SIGKILL, no output). "
                           "This is usually endpoint security (Carbon Black / Bitdefender) blocking it. "
                           "Check that `claude -p hi` works in Terminal." % claude)
        raise ApiError("Claude failed (exit %s): %s" % (proc.returncode, (final or {}).get("result") or err[-800:] or "no output"))
    return final, model_used or next(iter(final.get("modelUsage") or {}), None), session_id


def last_json_block(text):
    """The last parseable ```json {...}``` block in text, and the text before it."""
    for m in reversed(list(re.finditer(r"```json\s*(\{.*?\})\s*```", text, re.S))):
        try:
            return json.loads(m.group(1)), text[:m.start()].strip()
        except ValueError:
            continue
    return None, text.strip()


def load_project_context(loc):
    try:
        with open(project_context_path(loc)) as f:
            data = json.load(f)
        return data if isinstance(data.get("profile"), dict) else None
    except (OSError, ValueError, AttributeError):
        return None


def context_source_files(local, commit):
    raw = run_cmd(["git", "-C", local, "ls-tree", "-r", "-z", "--name-only", commit])
    preferred, manifests = [], []
    for path in (p for p in raw.split("\0") if p):
        normalized = path.replace("\\", "/")
        parts = normalized.split("/")
        name = parts[-1].lower()
        in_docs = any(p.lower() in ("doc", "docs", "documentation") for p in parts[:-1])
        if name in CONTEXT_EXACT_NAMES or name.startswith(("readme", "contributing", "architecture")):
            preferred.append(normalized)
        elif in_docs and name.endswith(".md") and any(
                word in name for word in ("arch", "design", "security", "test", "standard", "guide")):
            preferred.append(normalized)
        elif name in CONTEXT_MANIFEST_NAMES or name.endswith((".csproj", ".sln", ".xcodeproj")):
            manifests.append(normalized)
    return (sorted(set(preferred)) + sorted(set(manifests)))[:120]


def context_fingerprint(local, commit, sources):
    if not sources:
        return hashlib.sha256(b"project-context-v1:no-sources").hexdigest()
    tree = run_cmd(["git", "-C", local, "ls-tree", "-r", commit, "--"] + sources)
    return hashlib.sha256(("project-context-v1\n" + tree).encode()).hexdigest()


def save_project_context(loc, record):
    path = project_context_path(loc)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)


def ensure_project_context(job, cfg, loc, local, wt, target_commit, claude):
    sources = context_source_files(local, target_commit)
    fingerprint = context_fingerprint(local, target_commit, sources)
    cached = load_project_context(loc)
    if cached and cached.get("fingerprint") == fingerprint:
        job.note("Reusing project context from %s" % cached.get("generatedAt", "an earlier review"))
        return cached, True

    job.stage = "Analyzing project context"
    job.note("Building reusable project context (first review or architecture files changed)")
    checkout_worktree(job, local, wt, target_commit)
    prompt = PROJECT_CONTEXT_PROMPT.format(
        sources="\n".join("- `%s`" % path for path in sources) or "(No standard context files found; map the repository.)"
    )
    final, model, _ = run_claude(
        job, claude, prompt, wt, (cfg.get("reviewModel") or "").strip(),
        max_turns=20, allowed_tools=CONTEXT_TOOLS,
    )
    profile, before = last_json_block(final.get("result") or "")
    if not isinstance(profile, dict):
        raise ApiError("Claude did not return a valid project context profile: %s" % before[-500:])
    for key in ("architecture", "conventions", "testing", "security", "areas", "sources"):
        if not isinstance(profile.get(key), list):
            profile[key] = []
    record = {
        "fingerprint": fingerprint,
        "sourceCommit": target_commit,
        "generatedAt": iso(dt.datetime.utcnow()),
        "model": model,
        "sourceFiles": sources,
        "profile": profile,
    }
    save_project_context(loc, record)
    job.note("Saved reusable project context")
    return record, False


def project_context_for_slice(context, files):
    profile = (context or {}).get("profile") or {}
    selected = {
        "overview": profile.get("overview") or "",
        "architecture": (profile.get("architecture") or [])[:12],
        "conventions": (profile.get("conventions") or [])[:12],
        "testing": (profile.get("testing") or [])[:12],
        "security": (profile.get("security") or [])[:12],
        "areas": [],
    }
    lowered_files = [path.lower() for path in files]
    for area in profile.get("areas") or []:
        if not isinstance(area, dict):
            continue
        patterns = [
            str(p).lstrip("./") for p in area.get("paths") or []
            if re.search(r"[A-Za-z0-9]", str(p))
        ]
        name = str(area.get("name") or "").lower()
        relevant = any(
            fnmatch.fnmatch(path, pattern.lower()) or path.startswith(pattern.lower().rstrip("*"))
            for path in lowered_files for pattern in patterns
        ) or bool(name and any(name in path for path in lowered_files))
        if relevant:
            selected["areas"].append({
                "name": area.get("name"),
                "paths": patterns[:8],
                "guidance": (area.get("guidance") or [])[:6],
            })
    text = json.dumps(selected, indent=2)
    return text[:8000]


SEVERITY_RANK = {"critical": 0, "major": 1, "minor": 2, "nit": 3}


def link_findings(c, pid, findings):
    for f in findings:
        path = "/" + str(f.get("file") or "").lstrip("/")
        f["url"] = "%s?_a=files&path=%s" % (c.pr_web_url(pid), urllib.parse.quote(path))
    return findings


def low_signal_reason(path):
    parts = [p.lower() for p in path.replace("\\", "/").split("/")]
    name = parts[-1]
    ext = os.path.splitext(name)[1]
    if name in LOW_SIGNAL_NAMES or name.endswith((".lock", ".min.js", ".min.css", ".map")):
        return "generated or lock file"
    if any(p in GENERATED_PATH_PARTS for p in parts[:-1]):
        return "generated or vendored path"
    if ext in LOW_SIGNAL_EXTENSIONS:
        return "binary or visual resource"
    if ext == ".xml" and name not in HIGH_RISK_XML_NAMES and "navigation" not in parts[:-1]:
        return "ordinary XML resource"
    return None


def semantic_changes(wt, base):
    """Return semantic text changes and low-signal files without spending model context."""
    raw = run_cmd(["git", "-C", wt, "diff", "--name-status", "-z", "-M", "%s...HEAD" % base])
    tokens = iter(raw.split("\0"))
    entries = []
    for status in tokens:
        if not status:
            continue
        old_path = next(tokens, "")
        if status.startswith(("R", "C")):
            path = next(tokens, "")
        else:
            path = old_path
            old_path = None
        if path:
            entries.append((path, old_path))
    changes, skipped = [], []
    for path, old_path in sorted(entries):
        reason = low_signal_reason(path)
        if reason:
            skipped.append({"file": path, "reason": reason})
            continue
        if old_path:
            diff_args = ["%s:%s" % (base, old_path), "HEAD:%s" % path]
        else:
            diff_args = ["%s...HEAD" % base, "--", path]
        probe = subprocess.run(
            ["git", "-C", wt, "diff", "--quiet", "-w", "--ignore-blank-lines"] + diff_args,
            capture_output=True, text=True,
        )
        if probe.returncode == 0:
            skipped.append({"file": path, "reason": "formatting-only change"})
            continue
        if probe.returncode not in (0, 1):
            raise ApiError("Could not classify %s: %s" % (path, probe.stderr.strip() or "git diff failed"))
        stat = run_cmd(["git", "-C", wt, "diff", "--numstat"] + diff_args).splitlines()
        fields = stat[0].split("\t") if stat else []
        if len(fields) < 3 or fields[0] == "-" or fields[1] == "-":
            skipped.append({"file": path, "reason": "binary change"})
            continue
        added, deleted = int(fields[0]), int(fields[1])
        changes.append({"file": path, "added": added, "deleted": deleted, "lines": added + deleted})
    return changes, skipped


def feature_name(path):
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    lower = [p.lower() for p in parts]
    for i, part in enumerate(lower[:-1]):
        if part in FEATURE_PATH_MARKERS:
            return "/".join(parts[i:i + 2])
    if len(parts) == 1:
        return "repository root"
    parent = parts[-2]
    root = parts[0]
    return parent if parent == root else "%s/%s" % (root, parent)


def review_slices(changes):
    groups = {}
    for change in changes:
        groups.setdefault(feature_name(change["file"]), []).append(change)
    slices = []
    for feature in sorted(groups):
        batch, lines = [], 0
        for change in sorted(groups[feature], key=lambda c: c["file"]):
            if batch and (len(batch) >= REVIEW_MAX_FILES or lines + change["lines"] > REVIEW_MAX_LINES):
                slices.append((feature, batch))
                batch, lines = [], 0
            batch.append(change)
            lines += change["lines"]
        if batch:
            slices.append((feature, batch))
    counts = {}
    result = []
    for feature, batch in slices:
        counts[feature] = counts.get(feature, 0) + 1
        paths = [c["file"] for c in batch]
        digest = hashlib.sha256(("\0".join(paths)).encode()).hexdigest()[:12]
        result.append({
            "key": "%s:%s" % (feature, digest),
            "feature": feature,
            "featurePart": counts[feature],
            "files": paths,
            "changedLines": sum(c["lines"] for c in batch),
            "status": "pending",
        })
    totals = {}
    for item in result:
        totals[item["feature"]] = totals.get(item["feature"], 0) + 1
    for item in result:
        if totals[item["feature"]] > 1:
            item["label"] = "%s (part %s/%s)" % (
                item["feature"], item["featurePart"], totals[item["feature"]])
        else:
            item["label"] = item["feature"]
    return result


def aggregate_slice_results(record):
    completed = [s for s in record.get("slices") or [] if s.get("status") == "done"]
    findings, seen = [], set()
    for item in completed:
        for finding in (item.get("review") or {}).get("findings") or []:
            key = (
                str(finding.get("file") or "").lower(),
                str(finding.get("line") or ""),
                re.sub(r"\W+", " ", str(finding.get("title") or "").lower()).strip(),
            )
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity"), 9))
    verdicts = {(s.get("review") or {}).get("verdict") for s in completed}
    if any(f.get("severity") in ("critical", "major") for f in findings) or "needs_work" in verdicts:
        verdict = "needs_work"
    elif findings or "approve_with_suggestions" in verdicts:
        verdict = "approve_with_suggestions"
    else:
        verdict = "approve"
    summaries = []
    for item in completed:
        text = ((item.get("review") or {}).get("summary") or "").strip()
        if text:
            summaries.append("%s: %s" % (item.get("label"), text))
    prefix = "Reviewed %s feature slice%s covering %s semantic file%s; skipped %s low-signal file%s." % (
        len(completed), "" if len(completed) == 1 else "s",
        sum(len(s.get("files") or []) for s in completed),
        "" if sum(len(s.get("files") or []) for s in completed) == 1 else "s",
        len(record.get("skippedFiles") or []),
        "" if len(record.get("skippedFiles") or []) == 1 else "s",
    )
    detail = " ".join(summaries)
    record["review"] = {
        "verdict": verdict,
        "summary": (prefix + (" " + detail if detail else ""))[:3000],
        "findings": findings,
    }
    record["costUsd"] = sum(s.get("costUsd") or 0 for s in completed) or None
    record["turns"] = sum(s.get("turns") or 0 for s in completed) or None
    record["durationMs"] = sum(s.get("durationMs") or 0 for s in completed) or None
    models = [s.get("model") for s in completed if s.get("model")]
    record["model"] = models[-1] if models else None
    sessions = [s.get("sessionId") for s in completed if s.get("sessionId")]
    record["sessionId"] = sessions[0] if len(completed) == 1 and sessions else None


def review(job, cfg):
    c = Client(cfg)
    pid = job.pr_id
    job.stage = "Loading PR"
    pr = c.repo_api("pullRequests/%s" % pid)
    src = pr["sourceRefName"].replace("refs/heads/", "")
    tgt = pr["targetRefName"].replace("refs/heads/", "")
    local = detect_local_repo(cfg)
    claude = detect_claude(cfg)

    job.stage = "Fetching branches"
    job.note("git fetch %s, %s" % (src, tgt))
    src_ref, tgt_ref = "refs/repo-activity/pr-%s/source" % pid, "refs/repo-activity/pr-%s/target" % pid
    run_cmd(["git", "-c", "core.hooksPath=/dev/null", "-C", local, "fetch", "--no-tags", "--quiet", "origin",
             "+refs/heads/%s:%s" % (src, src_ref), "+refs/heads/%s:%s" % (tgt, tgt_ref)])
    head = run_cmd(["git", "-C", local, "rev-parse", src_ref]).strip()
    target_commit = run_cmd(["git", "-C", local, "rev-parse", tgt_ref]).strip()
    base = run_cmd(["git", "-C", local, "merge-base", src_ref, tgt_ref]).strip()

    wt = review_worktree(c.loc)
    context, context_reused = ensure_project_context(
        job, cfg, c.loc, local, wt, target_commit, claude)

    job.stage = "Checking out PR"
    checkout_worktree(job, local, wt, head)

    job.stage = "Classifying changes"
    changes, skipped = semantic_changes(wt, base)
    slices = review_slices(changes)
    job.note("%s semantic files in %s feature slices; %s low-signal files skipped" % (
        len(changes), len(slices), len(skipped)))

    previous = load_review(c.loc, pid)
    resumable = previous if previous and previous.get("incomplete") and \
        previous.get("sourceCommit") == head and previous.get("base") == base else None
    completed = {s.get("key"): s for s in (resumable or {}).get("slices") or [] if s.get("status") == "done"}
    for item in slices:
        if item["key"] in completed:
            item.update(completed[item["key"]])

    record = {
        "pr": pid, "title": pr.get("title", ""), "url": c.pr_web_url(pid), "sourceCommit": head,
        "base": base, "at": iso(dt.datetime.utcnow()), "review": {}, "slices": slices,
        "skippedFiles": skipped, "incomplete": True,
        "projectContext": {
            "generatedAt": context.get("generatedAt"),
            "sourceCommit": context.get("sourceCommit"),
            "fingerprint": context.get("fingerprint"),
            "reused": context_reused,
        },
    }
    os.makedirs(os.path.dirname(review_cache_path(c.loc, pid)), exist_ok=True)
    aggregate_slice_results(record)
    save_review(c.loc, record)

    reviewed_this_run = 0
    for index, item in enumerate(slices):
        if item.get("status") == "done":
            job.note("Reusing completed slice %s/%s: %s" % (index + 1, len(slices), item["label"]))
            continue
        if reviewed_this_run >= REVIEW_SLICES_PER_RUN:
            break
        job.stage = "Reviewing feature %s / %s" % (index + 1, len(slices))
        job.note("%s · %s files · %s changed lines" % (
            item["label"], len(item["files"]), item["changedLines"]))
        prompt = SLICE_REVIEW_PROMPT.format(
            id=pid, title=pr.get("title", ""), author=(pr.get("createdBy") or {}).get("displayName", ""),
            source=src, target=tgt, base=base[:12], feature=item["label"],
            part=index + 1, total=len(slices), description=(pr.get("description") or "(none)")[:2500],
            project_context=project_context_for_slice(context, item["files"]),
            files="\n".join("- `%s`" % path for path in item["files"]),
        )
        try:
            final, model, session_id = run_claude(
                job, claude, prompt, wt, (cfg.get("reviewModel") or "").strip(),
                max_turns=REVIEW_MAX_TURNS,
            )
        except Exception:
            aggregate_slice_results(record)
            save_review(c.loc, record)
            raise
        parsed, before = last_json_block(final.get("result") or "")
        if parsed is None:
            parsed = {"verdict": None, "summary": before, "findings": []}
        parsed["findings"] = link_findings(c, pid, parsed.get("findings") or [])
        item.update({
            "status": "done", "review": parsed, "model": model, "sessionId": session_id,
            "costUsd": final.get("total_cost_usd"), "turns": final.get("num_turns"),
            "durationMs": final.get("duration_ms"),
        })
        reviewed_this_run += 1
        aggregate_slice_results(record)
        save_review(c.loc, record)

    remaining = sum(s.get("status") != "done" for s in slices)
    if remaining:
        job.note("Paused with %s feature slice%s remaining; continue when ready" % (
            remaining, "" if remaining == 1 else "s"))
        aggregate_slice_results(record)
        save_review(c.loc, record)
        job.result = record
        job.stage = "Paused"
        return

    record["incomplete"] = False
    aggregate_slice_results(record)
    save_review(c.loc, record)
    job.result = record
    job.stage = "Done"


ASK_PROMPT = """Follow-up from the reviewer about your code review of pull request !{id}:

{question}

Answer the reviewer directly. Use the tools to read the diff and code as needed; do not modify files.
If this leads you to NEW problems that are not already in the review, end your answer with ONE fenced ```json
block {{"findings": [...]}} using exactly the same finding shape as the review (severity, file, line, title,
detail, suggestion). Never repeat a finding that is already in the review. Omit the block if there are none.
"""

ASK_CONTEXT = """(Context: the original review session is not available, so here is what it contained.)
PR !{id} "{title}". The current directory is checked out at the PR's source commit (HEAD); the PR's changes are
exactly `git diff {base}...HEAD`.
Existing review verdict: {verdict}. Summary: {summary}
Existing findings (do not repeat these):
{findings}

"""


def ask(job, cfg, question, allow_resume=True):
    c = Client(cfg)
    pid = job.pr_id
    record = load_review(c.loc, pid)
    if not record:
        raise ApiError("No AI review saved for this PR yet.", 404)
    if record.get("incomplete"):
        raise ApiError("Finish all feature slices before asking follow-up questions.", 409)
    local = detect_local_repo(cfg)
    claude = detect_claude(cfg)

    # Follow-ups must see the same code the review saw, even if the worktree moved to another PR since.
    job.stage = "Checking out reviewed commit"
    wt = review_worktree(c.loc)
    checkout_worktree(job, local, wt, record["sourceCommit"])

    review_data = record.get("review") or {}
    prompt = ASK_PROMPT.format(id=pid, question=question.strip())
    resume = record.get("sessionId") if allow_resume else None
    if not resume:
        prompt = ASK_CONTEXT.format(
            id=pid, title=record.get("title", ""), base=(record.get("base") or "")[:12],
            verdict=review_data.get("verdict"), summary=review_data.get("summary") or "",
            findings="\n".join("- [%s] %s (%s:%s)" % (f.get("severity"), f.get("title"), f.get("file"), f.get("line"))
                               for f in review_data.get("findings") or []) or "(none)") + prompt

    job.stage = "Claude is answering"
    job.note("Q: " + question.strip().splitlines()[0])
    try:
        final, model, session_id = run_claude(job, claude, prompt, wt, (cfg.get("reviewModel") or "").strip(), resume)
    except ApiError as e:
        if not resume or "Cancelled" in str(e):
            raise
        # The session can disappear (CLI cleanup, another machine): fall back to a fresh one with context.
        job.note("Original review session unavailable; starting a new one with the review as context")
        return ask(job, cfg, question, allow_resume=False)

    parsed, answer = last_json_block(final.get("result") or "")
    existing = {(str(f.get("file")), str(f.get("line")), (f.get("title") or "").lower())
                for f in review_data.get("findings") or []}
    new = [f for f in (parsed or {}).get("findings") or []
           if (str(f.get("file")), str(f.get("line")), (f.get("title") or "").lower()) not in existing]
    for f in new:
        f["fromFollowup"] = len(record.get("followups") or []) + 1
    review_data["findings"] = sorted((review_data.get("findings") or []) + link_findings(c, pid, new),
                                     key=lambda f: SEVERITY_RANK.get(f.get("severity"), 9))
    record["review"] = review_data
    record["sessionId"] = session_id or resume
    record.setdefault("followups", []).append({
        "q": question.strip(), "a": answer, "at": iso(dt.datetime.utcnow()), "model": model,
        "newFindings": len(new), "costUsd": final.get("total_cost_usd"), "turns": final.get("num_turns"),
        "durationMs": final.get("duration_ms"),
    })
    save_review(c.loc, record)
    job.result = record
    job.stage = "Done"


# ---------------------------------------------------------------- post review to the PR

def model_label(model_id):
    """'claude-opus-4-5-20251101' -> 'Claude Opus 4.5'; unknown -> 'an AI model'."""
    if not model_id:
        return "an AI model"
    parts = [p for p in re.sub(r"\[.*?\]", "", model_id).split("-") if not re.fullmatch(r"\d{8}", p)]
    words = [p.capitalize() for p in parts if not p.isdigit()]
    version = ".".join(p for p in parts if p.isdigit())
    return " ".join(words + ([version] if version else []))


def ai_footer(record):
    return ("\n\n---\n_AI review by %s (posted from Repo Activity). Please verify before acting on it._"
            % model_label(record.get("model")))
VERDICT_LABELS = {"approve": "Looks good", "approve_with_suggestions": "Approve with suggestions",
                  "needs_work": "Needs work"}
THREAD_ACTIVE, THREAD_CLOSED = 1, 4


def save_review(loc, record):
    path = review_cache_path(loc, record["pr"])
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)


def finding_line(f):
    m = re.match(r"\s*(\d+)", str(f.get("line") or ""))
    return int(m.group(1)) if m else None


def finding_comment(f, with_location, footer):
    text = "**[AI review · %s] %s**" % (f.get("severity") or "note", f.get("title") or "")
    if with_location and f.get("file"):
        line = finding_line(f)
        text += "\n\n`%s%s`" % (f["file"], ":%d" % line if line else "")
    if f.get("detail"):
        text += "\n\n" + f["detail"]
    if f.get("suggestion"):
        sep = "\n\n" if f["suggestion"].lstrip().startswith("```") else " "
        text += "\n\n**Suggestion:**" + sep + f["suggestion"]
    return text + footer


def post_review(cfg, pid, indices, include_summary):
    c = Client(cfg)
    record = load_review(c.loc, pid)
    if not record:
        raise ApiError("No AI review saved for this PR.", 404)
    if record.get("incomplete"):
        raise ApiError("The AI review is incomplete. Continue it before posting.", 409)
    pr = c.repo_api("pullRequests/%s" % pid)
    if pr.get("status") != "active":
        raise ApiError("PR !%s is %s; not posting." % (pid, pr.get("status")), 409)
    latest = (pr.get("lastMergeSourceCommit") or {}).get("commitId")
    if latest and latest != record.get("sourceCommit"):
        raise ApiError("New commits were pushed after this review, so line numbers may have moved. "
                       "Re-run the review before posting.", 409)

    # Anchor comments to the latest iteration so they land on the right line in the Files view.
    iterations = c.repo_api("pullRequests/%s/iterations" % pid).get("value", [])
    last_iter = max((i["id"] for i in iterations), default=None)
    tracking = {}
    if last_iter:
        changes = c.repo_api("pullRequests/%s/iterations/%s/changes" % (pid, last_iter), {"$top": 2000})
        tracking = {e["item"]["path"]: e.get("changeTrackingId")
                    for e in changes.get("changeEntries", []) if (e.get("item") or {}).get("path")}

    findings = (record.get("review") or {}).get("findings") or []
    posted = 0
    for i in indices:
        if not 0 <= i < len(findings) or findings[i].get("posted"):
            continue
        f = findings[i]
        path = "/" + str(f.get("file") or "").lstrip("/")
        line = finding_line(f)
        inline = bool(line and path in tracking)
        body = {"comments": [{"parentCommentId": 0, "commentType": 1,
                              "content": finding_comment(f, not inline, ai_footer(record))}],
                "status": THREAD_ACTIVE}
        if inline:
            body["threadContext"] = {"filePath": path, "rightFileStart": {"line": line, "offset": 1},
                                     "rightFileEnd": {"line": line, "offset": 1}}
            body["pullRequestThreadContext"] = {
                "changeTrackingId": tracking[path],
                "iterationContext": {"firstComparingIteration": 1, "secondComparingIteration": last_iter}}
        thread = c.repo_post("pullRequests/%s/threads" % pid, body)
        f["posted"] = {"threadId": thread.get("id"), "at": iso(dt.datetime.utcnow()), "inline": inline}
        save_review(c.loc, record)  # persist after each post so a failure midway never double-posts
        posted += 1

    if include_summary and not record.get("summaryPosted"):
        review = record.get("review") or {}
        lines = ["**AI review: %s**" % VERDICT_LABELS.get(review.get("verdict"), "Summary"), "",
                 review.get("summary") or ""]
        if findings:
            lines += ["", "Findings:"] + ["- **%s** %s (`%s%s`)" % (
                f.get("severity"), f.get("title"), f.get("file"), ":%s" % finding_line(f) if finding_line(f) else "")
                for f in findings]
        thread = c.repo_post("pullRequests/%s/threads" % pid, {
            "comments": [{"parentCommentId": 0, "commentType": 1, "content": "\n".join(lines) + ai_footer(record)}],
            "status": THREAD_CLOSED})  # informational: must not block the comment-resolution policy
        record["summaryPosted"] = {"threadId": thread.get("id"), "at": iso(dt.datetime.utcnow())}
        save_review(c.loc, record)
        posted += 1
    return {"posted": posted, "record": record}


# ---------------------------------------------------------------- HTTP server

last_request = [time.time()]


class Handler(BaseHTTPRequestHandler):
    server_version = "RepoActivity/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _guard(self):
        # Only answer requests the local UI makes (blocks DNS-rebinding / cross-site calls).
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(403, {"error": "forbidden"})
            return False
        if self.command == "POST" and self.headers.get("X-Repo-Activity") != "1":
            self._send(403, {"error": "forbidden"})
            return False
        return True

    def do_GET(self):
        last_request[0] = time.time()
        if not self._guard():
            return
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        try:
            if url.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif url.path == "/api/ping":
                self._send(200, {"app": "repo-activity", "version": APP_VERSION})
            elif url.path == "/api/config":
                cfg = load_config()
                cfg["hasPat"] = keychain_get() is not None
                try:  # what "CLI default" currently means, for the model dropdown's label
                    with open(os.path.expanduser("~/.claude/settings.json")) as f:
                        cfg["claudeDefaultModel"] = json.load(f).get("model")
                except (OSError, ValueError):
                    cfg["claudeDefaultModel"] = None
                for key, fn in (("localRepoDetected", detect_local_repo), ("claudeDetected", detect_claude)):
                    try:
                        cfg[key] = fn(cfg)
                    except Exception:
                        cfg[key] = None
                self._send(200, cfg)
            elif url.path == "/api/job":
                job = JOBS.get(q.get("id"))
                self._send(200, job.to_json()) if job else self._send(404, {"error": "unknown job"})
            elif url.path == "/api/lookup":
                self._send(200, {"value": lookup_identities(load_config(), q.get("q", ""))})
            elif url.path == "/api/prs":
                self._send(200, {"value": list_active_prs(load_config())})
            elif url.path == "/api/review":
                pid = int(q["id"])
                job = REVIEW_JOBS.get(pid)
                if job and (not job.finished or job.error):
                    self._send(200, job.to_json())
                else:
                    cfg = load_config()
                    cached = load_review(parse_repo_url(cfg["repoUrl"]), pid)
                    stage = "Paused" if cached and cached.get("incomplete") else "Done" if cached else "None"
                    self._send(200, {"id": pid, "finished": True, "result": cached, "stage": stage,
                                     "log": job.log if job else [], "error": None})
            elif url.path == "/api/user":
                self._send(200, user_detail(load_config(), q["id"], int(q.get("days") or 60)))
            else:
                self._send(404, {"error": "not found"})
        except ApiError as e:
            self._send(502 if not e.status or e.status >= 500 else e.status, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_POST(self):
        last_request[0] = time.time()
        if not self._guard():
            return
        path = urllib.parse.urlsplit(self.path).path
        try:
            body = self._body()
            if path == "/api/config":
                cfg = load_config()
                for k in DEFAULTS:
                    if k in body:
                        cfg[k] = body[k]
                parse_repo_url(cfg["repoUrl"])
                cfg["days"] = max(1, min(730, int(cfg["days"])))
                if cfg["auth"] not in ("pat", "git"):
                    raise ApiError("Unknown auth mode", 400)
                if cfg.get("reviewModel") and not re.fullmatch(r"[A-Za-z0-9._\[\]-]{1,64}", cfg["reviewModel"]):
                    raise ApiError("Invalid model id", 400)
                if body.get("pat"):
                    keychain_set(body["pat"].strip())
                if body.get("clearPat"):
                    keychain_delete()
                save_config(cfg)
                _git_creds.clear()
                cfg["hasPat"] = keychain_get() is not None
                self._send(200, cfg)
            elif path == "/api/test":
                c = Client(load_config())
                repo = c.repo_api("")
                self._send(200, {"name": repo.get("name"), "defaultBranch": repo.get("defaultBranch"),
                                 "project": (repo.get("project") or {}).get("name")})
            elif path == "/api/scan":
                cfg = load_config()
                for k in ("days", "deep"):
                    if k in body:
                        cfg[k] = body[k]
                save_config(cfg)
                job = Job()
                JOBS.clear()  # keep memory bounded; only the latest scan matters
                JOBS[job.id] = job
                threading.Thread(target=run_scan, args=(job, cfg), daemon=True).start()
                self._send(200, {"id": job.id})
            elif path == "/api/review":
                pid = int(body["id"])
                job = REVIEW_JOBS.get(pid)
                if not job or job.finished:
                    job = REVIEW_JOBS[pid] = ReviewJob(pid)
                    if REVIEW_LOCK.locked():
                        job.note("Waiting for the running review to finish")
                    threading.Thread(target=run_review, args=(job, load_config()), daemon=True).start()
                self._send(200, job.to_json())
            elif path == "/api/review/ask":
                pid = int(body["id"])
                question = (body.get("question") or "").strip()
                if not question:
                    raise ApiError("Type a question first.", 400)
                job = REVIEW_JOBS.get(pid)
                if job and not job.finished:
                    raise ApiError("A review or follow-up for this PR is already running.", 409)
                job = REVIEW_JOBS[pid] = ReviewJob(pid)
                if REVIEW_LOCK.locked():
                    job.note("Waiting for the running review to finish")
                threading.Thread(target=run_review, daemon=True,
                                 args=(job, load_config(), lambda j, cfg: ask(j, cfg, question))).start()
                self._send(200, job.to_json())
            elif path == "/api/review/post":
                self._send(200, post_review(load_config(), int(body["id"]),
                                            [int(i) for i in body.get("findings") or []], bool(body.get("summary"))))
            elif path == "/api/review/cancel":
                job = REVIEW_JOBS.get(int(body["id"]))
                if job and not job.finished:
                    job.cancelled = True
                    if job.proc:
                        job.proc.kill()
                self._send(200, {"ok": True})
            elif path == "/api/heartbeat":
                self._send(200, {"ok": True})
            elif path == "/api/quit":
                self._send(200, {"ok": True})
                threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()
            else:
                self._send(404, {"error": "not found"})
        except (ApiError, ValueError) as e:
            status = getattr(e, "status", None) or 400
            self._send(status if status < 600 else 400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


def already_running():
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % PORT, timeout=2) as r:
            return json.load(r).get("app") == "repo-activity"
    except Exception:
        return False


def idle_watchdog():
    while True:
        time.sleep(30)
        busy = any(not j.finished for j in list(JOBS.values()) + list(REVIEW_JOBS.values()))
        if not busy and time.time() - last_request[0] > IDLE_EXIT_SECONDS:
            os._exit(0)


def main():
    url = "http://127.0.0.1:%d/" % PORT
    no_browser = "--no-browser" in sys.argv
    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError:
        if already_running():
            if not no_browser:
                webbrowser.open(url)
            return
        raise
    threading.Thread(target=idle_watchdog, daemon=True).start()
    print("Repo Activity running at " + url, flush=True)
    if not no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
