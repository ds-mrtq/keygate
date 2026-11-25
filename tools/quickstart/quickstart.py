#!/usr/bin/env python3
"""Runs the README quick start as written, so the docs and CI cannot drift.

The commands come from the fenced blocks that follow a `<!-- quickstart:<name> -->` marker in
README.md. Only the download locations are rewritten, to a local server holding the release
archives built by CI. Fake passwords and a fake secret value are typed at the prompts.

  quickstart.py check [--external]                 EN/VI blocks equal, links resolve
  quickstart.py linux   --dist DIR --version TAG   Linux install + first run under a pty
  quickstart.py windows --dist DIR --version TAG   Windows install + kg init (stops at Hello)
"""
import argparse, functools, http.server, os, re, shutil, subprocess, sys, tempfile, threading, time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
READMES = ["README.md", "README.vi.md"]
RAW = "https://raw.githubusercontent.com/ds-mrtq/keygate/main/"
DOWNLOAD = "https://github.com/ds-mrtq/keygate/releases/download/"

MASTER, DEVICE, VALUE = "fake-master-pw-0123", "fake-device-pw-4567", "fake-Value-9f3k2Q"
# README prompt table entry -> what CI types. Every prompt answered must be listed in both READMEs.
ANSWERS = {
    "Mật khẩu chủ (>= 12 ký tự):": MASTER,
    "Nhập lại mật khẩu chủ:": MASTER,
    "Mật khẩu mở khóa thiết bị để duyệt:": DEVICE,
    "Mật khẩu mở khóa thiết bị:": DEVICE,
    "Nhập lại:": DEVICE,
    '[broker] Nhập giá trị cho "demo/token"': VALUE,
}
MASKED = "deploying with token [kg:demo/token]"


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def blocks(text):
    out = {}
    for m in re.finditer(r"<!-- quickstart:([\w-]+) -->\n```\w*\n(.*?)\n```", text, re.S):
        out[m.group(1)] = m.group(2)
    return out


def strip_comments(block):
    return "\n".join(re.sub(r"\s{2,}#\s.*$", "", l).rstrip() for l in block.splitlines())


def slug(heading):
    s = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return s.replace(" ", "-")


def cmd_check(args):
    en, vi = blocks(read("README.md")), blocks(read("README.vi.md"))
    want = ["linux-install-script", "linux-install-manual", "windows-install-script",
            "windows-install-manual", "linux-terminal-1", "linux-terminal-2", "windows-init"]
    for name in want:
        if name not in en or name not in vi:
            die(f"block quickstart:{name} missing from README.md or README.vi.md")
        if strip_comments(en[name]) != strip_comments(vi[name]):
            die(f"block quickstart:{name} differs between README.md and README.vi.md")
    for readme in READMES:
        text = read(readme)
        for p in ANSWERS:
            if f"`{p}" not in text:
                die(f"{readme}: prompt {p!r} missing from the prompt table")
        anchors = {slug(h) for h in re.findall(r"^#+ (.*)$", text, re.M)}
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if target.startswith(("http://", "https://")):
                if args.external:
                    check_url(readme, target)
            elif target.startswith("#"):
                if target[1:] not in anchors:
                    die(f"{readme}: no heading for link {target}")
            elif not os.path.exists(os.path.join(ROOT, target.split("#")[0])):
                die(f"{readme}: link target {target} does not exist")
    print("quickstart check: blocks match in EN and VI, prompts listed, links resolve")


def check_url(readme, url):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "keygate-quickstart-check"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30):
                return
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                die(f"{readme}: {url} returns {e.code}")
        except OSError:
            pass
        time.sleep(5)
    print(f"warning: {readme}: could not reach {url}", file=sys.stderr)


def serve(dist, version):
    """Serves raw/<install scripts> and <version>/<release files> on 127.0.0.1."""
    srv = tempfile.mkdtemp(prefix="kg-qs-srv-")
    os.makedirs(os.path.join(srv, "raw"))
    for s in ("install.sh", "install.ps1"):
        shutil.copy(os.path.join(ROOT, s), os.path.join(srv, "raw", s))
    shutil.copytree(dist, os.path.join(srv, version))
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=srv)
    handler.log_message = lambda *a: None
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{httpd.server_address[1]}/", srv


def rewrite(block, base, version):
    block = block.replace(RAW, base + "raw/").replace(DOWNLOAD, base)
    block = re.sub(r"^VERSION=v0\.1\.0$", f"VERSION={version}", block, flags=re.M)
    return re.sub(r"^\$Version = 'v0\.1\.0'$", f"$Version = '{version}'", block, flags=re.M)


def show(title, text):
    text = re.sub(r"(KHÓA GIẤY[^\n]*\n\s*\n\s*)\S[^\n]*", r"\1<paper key hidden>", text)
    print(f"----- {title} -----\n{text.rstrip()}\n")


def expect(text, want, what):
    if want not in text:
        die(f"{what}: expected {want!r} in the output")


def clean_env():
    env = dict(os.environ)
    for k in ("KG_HOME", "KG_DEVKEY_BACKEND", "KG_TEST_APPROVE", "KG_VERSION", "KG_BASE_URL", "KG_INSTALL_DIR"):
        env.pop(k, None)
    return env


class Term:
    """A terminal: runs argv under a pseudo-terminal and types the answer to each known prompt."""

    def __init__(self, argv, env, cwd=None):
        import pty
        self.screen, self.pos, self.answered, self.status = "", 0, set(), None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            if cwd:
                os.chdir(cwd)
            os.execvpe(argv[0], argv, env)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                data = os.read(self.fd, 4096)
            except OSError:
                return
            if not data:
                return
            self.screen += data.decode(errors="replace")
            while True:
                rest, hit = self.screen[self.pos:], None
                for p, a in ANSWERS.items():
                    i = rest.find(p)
                    if i >= 0 and (hit is None or i < hit[0] or (i == hit[0] and len(p) > len(hit[1]))):
                        hit = (i, p, a)
                if hit is None:
                    break
                self.pos += hit[0] + len(hit[1])
                self.answered.add(hit[1])
                time.sleep(0.3)
                os.write(self.fd, (hit[2] + "\n").encode())

    def wait_for(self, text, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.screen:
                return True
            if self.poll() is not None:
                return text in self.screen
            time.sleep(0.2)
        return False

    def poll(self):
        if self.status is None:
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(st)
        return self.status

    def wait(self, timeout):
        end = time.time() + timeout
        while self.poll() is None:
            if time.time() > end:
                os.kill(self.pid, 9)
                die("timed out:\n" + self.screen)
            time.sleep(0.2)
        time.sleep(0.5)
        return self.status


def run(argv, env, cwd=None, stdin=None):
    r = subprocess.run(argv, env=env, cwd=cwd, input=stdin, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return r.returncode, r.stdout + r.stderr


def cmd_linux(args):
    bl = blocks(read("README.md"))
    base, srv = serve(args.dist, args.version)
    env = clean_env()
    home = env["HOME"]
    bindir = os.path.join(home, ".local", "bin")
    vline = f"kg {args.version} (commit "

    # install.sh needs a tag when no release is published yet; KG_BASE_URL serves the CI archives.
    script = rewrite(bl["linux-install-script"], base, args.version)
    code, out = run(["bash", "-euo", "pipefail", "-c", script],
                    dict(env, KG_VERSION=args.version, KG_BASE_URL=os.path.join(srv, args.version)))
    show("linux-install-script", out)
    if code:
        die(f"install script exited {code}")
    expect(out, vline, "install script")
    shutil.rmtree(bindir)

    work = tempfile.mkdtemp(prefix="kg-qs-manual-")
    code, out = run(["bash", "-euo", "pipefail", "-c", rewrite(bl["linux-install-manual"], base, args.version)], env, cwd=work)
    show("linux-install-manual", out)
    if code:
        die(f"manual install exited {code}")
    expect(out, ": OK", "sha256sum -c")
    expect(out, vline, "kg version")

    env["PATH"] = bindir + os.pathsep + env["PATH"]
    t1 = Term(["bash", "-c", bl["linux-terminal-1"]], env, cwd=home)
    if not t1.wait_for("[broker] đã mở khóa", 120):
        die("broker did not unlock:\n" + t1.screen)
    t2 = Term(["bash", "-euo", "pipefail", "-c", bl["linux-terminal-2"]], env, cwd=home)
    code = t2.wait(300)
    os.kill(t1.pid, 2)
    t1.wait(30)
    show("terminal 1 (broker)", t1.screen)
    show("terminal 2", t2.screen)
    if code:
        die(f"terminal 2 exited {code}")
    expect(t2.screen, MASKED, "kg run")
    expect(t1.screen, "để duyệt", "approval at the broker's terminal")
    lines = t2.screen.splitlines()
    if not any(re.search(r" policy .*approval=tty-password", l) for l in lines):
        die("kg audit show must list the policy approved at the broker's terminal")
    audit = [l for l in lines if re.search(r" run +demo/token .*exit=0 .*demo\.sh", l)]
    if not audit:
        die("kg audit show must list the run of the demo script")
    for secret in (VALUE, MASTER, DEVICE):
        if secret in t1.screen or secret in t2.screen:
            die("a typed secret was echoed")
    for p in ANSWERS:
        if p not in t1.answered | t2.answered:
            die(f"documented prompt never appeared: {p!r}")
    print(f"OK: masked output {MASKED!r}; audit: {audit[-1].strip()}")


def cmd_windows(args):
    bl = blocks(read("README.md"))
    base, srv = serve(args.dist, args.version)
    env = clean_env()
    install_dir = os.path.join(env["LOCALAPPDATA"], "Programs", "KeyGate")
    vline = f"kg {args.version} (commit "

    def ps(name, extra_env=None, stdin=None, cwd=None):
        path = os.path.join(tempfile.mkdtemp(prefix="kg-qs-"), name + ".ps1")
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write("$ErrorActionPreference = 'Stop'\n" + rewrite(bl[name], base, args.version) + "\n")
        e = dict(env, **(extra_env or {}))
        code, out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path], e, cwd=cwd, stdin=stdin)
        show(name, out)
        if code:
            die(f"{name} exited {code}")
        return out

    out = ps("windows-install-script", {"KG_VERSION": args.version, "KG_BASE_URL": os.path.join(srv, args.version)})
    expect(out, vline, "install script")
    shutil.rmtree(install_dir)

    out = ps("windows-install-manual", cwd=tempfile.mkdtemp(prefix="kg-qs-manual-"))
    expect(out, vline, "kg version")

    env["PATH"] = install_dir + os.pathsep + env["PATH"]
    out = ps("windows-init", stdin=f"{MASTER}\n{MASTER}\n")
    expect(out, "KHÓA GIẤY", "kg init")
    if MASTER in out:
        die("the master password was echoed")
    print("OK through kg init. Not run on CI: `kgw tray` and every later step need Windows Hello.")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--external", action="store_true", help="also fetch http(s) links")
    for name in ("linux", "windows"):
        p = sub.add_parser(name)
        p.add_argument("--dist", required=True, help="directory with the release archives and SHA256SUMS")
        p.add_argument("--version", required=True)
    args = ap.parse_args()
    {"check": cmd_check, "linux": cmd_linux, "windows": cmd_windows}[args.cmd](args)


if __name__ == "__main__":
    main()
