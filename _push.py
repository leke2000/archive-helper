"""Update the GitHub repo with the current project state (no git required).

Uploads all project files in one commit through the Git Data API.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
ROOT = os.path.dirname(os.path.abspath(__file__))
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "build", "dist"}
SKIP_FILES = {".DS_Store", "Thumbs.db", "_publish.py", "_update.py"}


def req(method, url, token, data=None, retries=4):
    body = json.dumps(data).encode() if data is not None else None
    last = None
    for attempt in range(retries):
        r = urllib.request.Request(url, data=body, method=method)
        r.add_header("Authorization", "Bearer " + token)
        r.add_header("Accept", "application/vnd.github+json")
        r.add_header("User-Agent", "publish-script")
        if body:
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r, timeout=90) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode(errors="replace")
        except Exception as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"请求失败 {method} {url}: {last}")


def collect(root):
    files = []
    for r, dirs, fs in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in fs:
            if f in SKIP_FILES:
                continue
            p = os.path.join(r, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            files.append((rel, p))
    return sorted(files)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    owner, repo, token = sys.argv[1], sys.argv[2], sys.argv[3]
    message = sys.argv[4] if len(sys.argv) > 4 else "更新"

    st, ref = req("GET", f"{API}/repos/{owner}/{repo}/git/ref/heads/main", token)
    if st != 200:
        print("读取分支失败:", st, ref)
        return 1
    base_commit = ref["object"]["sha"]

    st, cur = req("GET", f"{API}/repos/{owner}/{repo}/git/commits/{base_commit}", token)
    if st != 200:
        print("读取提交失败:", st, cur)
        return 1
    st, base_tree = req("GET", f"{API}/repos/{owner}/{repo}/git/trees/{cur['tree']['sha']}", token)
    if st != 200:
        print("读取 tree 失败:", st, base_tree)
        return 1

    local = collect(ROOT)
    local_paths = {rel for rel, _ in local}
    remote_paths = {e["path"] for e in base_tree.get("tree", []) if e.get("type") == "blob"}

    tree = []
    for rel, path in local:
        with open(path, "rb") as f:
            content = f.read()
        st, blob = req("POST", f"{API}/repos/{owner}/{repo}/git/blobs", token, {
            "content": base64.b64encode(content).decode(),
            "encoding": "base64",
        })
        if st not in (200, 201):
            print(f"上传失败 {rel}: {st} {blob}")
            return 1
        tree.append({"path": rel, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        print("  +", rel)

    for rel in sorted(remote_paths - local_paths):
        tree.append({"path": rel, "mode": "100644", "type": "blob", "sha": None})
        print("  -", rel)

    st, t = req("POST", f"{API}/repos/{owner}/{repo}/git/trees", token, {"tree": tree})
    if st not in (200, 201):
        print("创建 tree 失败:", st, t)
        return 1

    st, commit = req("POST", f"{API}/repos/{owner}/{repo}/git/commits", token, {
        "message": message,
        "tree": t["sha"],
        "parents": [base_commit],
    })
    if st not in (200, 201):
        print("创建 commit 失败:", st, commit)
        return 1

    st, r = req("PATCH", f"{API}/repos/{owner}/{repo}/git/refs/heads/main", token,
                {"sha": commit["sha"], "force": False})
    if st not in (200, 201):
        print("更新分支失败:", st, r)
        return 1

    print()
    print("更新完成:", commit["sha"][:8])
    return 0


if __name__ == "__main__":
    sys.exit(main())
