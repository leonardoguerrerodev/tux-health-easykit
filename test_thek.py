#!/usr/bin/env python3
"""Self-checks. Run: python3 test_thek.py  (prints "ok")."""
import ast
import builtins
import getpass
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix="thek-test-")
os.environ["XDG_DATA_HOME"] = TMP  # never touch the real reports
os.environ["THEK_LANG"] = "en"

import actions  # noqa: E402
import checks  # noqa: E402
import i18n  # noqa: E402
import THEK_run as thek  # noqa: E402

# tokens are assembled at runtime so this file itself never matches the secret patterns
GHP = "gh" + "p_" + "A1b2C3d4E5" * 3 + "ZZZZZZ"
HF = "h" + "f_" + "abcdEFGH12" * 3 + "xyz"


def test_family():
    cases = {
        'ID=nobara\nID_LIKE="rhel centos fedora"\nVERSION_ID=44': "fedora",
        "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04": "debian",
        "ID=debian\nVERSION_ID=12": "debian",
        "ID=arch\n": "arch",
        'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"': "suse",
        'ID="rocky"\nID_LIKE="rhel centos fedora"': "fedora",
        "ID=alpine\n": "unknown",
    }
    for text, fam in cases.items():
        assert checks.family_of(checks.parse_os_release(text)) == fam, (text, fam)


def test_split_probes():
    out = "### THEK:a\nline1\nline2\n### END:a:0\n### THEK:b\nx\n### END:b:3\n### THEK:c\ncut"
    p = checks.split_probes(out)
    assert p["a"] == (0, "line1\nline2") and p["b"] == (3, "x") and p["c"] == (None, "cut")
    assert checks.split_probes("sudo: a password is required") == {}


def test_parsers():
    assert actions.parse_clamscan("/tmp/x/eicar.com: Eicar-Test-Signature FOUND\n/ok\n") == \
        [("/tmp/x/eicar.com", "Eicar-Test-Signature")]
    rpm = "S.5....T.  c /etc/x\n..5......    /usr/bin/x\n.......T.    /usr/lib/y\nmissing     /usr/bin/z"
    assert checks.parse_integrity("fedora", rpm) == ["..5......    /usr/bin/x"]
    pac = "warning: coreutils: /usr/bin/ls (SHA256 checksum mismatch)\nwarning: x: /etc/y (Modification time mismatch)"
    assert len(checks.parse_integrity("arch", pac)) == 1
    deb = "debsums: changed file /usr/bin/x (from foo package)\ndebsums: changed file /etc/z (from foo package)"
    assert len(checks.parse_integrity("debian", deb)) == 1
    assert checks.parse_rkhunter("Checking...\nWarning: The file properties have changed:\nok") == \
        ["Warning: The file properties have changed:"]
    idx, w = checks.parse_lynis("hardening_index=65\nwarning[]=SSH-7408|x|\nsuggestion[]=A|b|")
    assert idx == "65" and w == ["SSH-7408|x|"]
    ss = ('udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n'
          'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
          'tcp LISTEN 0 4096 [::1]:631 [::]:*\n'
          'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))')
    exposed = [a for _, a, _ in checks.parse_ss(ss) if not checks.is_loopback(a)]
    assert exposed == ["0.0.0.0:5353", "0.0.0.0:22"], exposed
    assert checks.parse_sshd("passwordauthentication yes\npermitrootlogin no") == ["passwordauthentication yes"]
    smart = "== sda\nSMART overall-health self-assessment test result: PASSED\n== zram0\nUnable to detect device type\n== sdb\nresult: FAILED!"
    assert [s for _, s, _ in checks.parse_smart(smart)] == ["OK", "UNKNOWN", "FAILED"]
    assert checks.clamav_db_age_days("ClamAV 1.4.6/28080/Sun Aug  2 02:24:19 2026", now=1785637459 + 10 * 86400) in (9, 10, 11)
    assert checks.parse_authorized_key('from="x",command="a b" ssh-ed25519 AAAAC3 me@laptop') == \
        "ssh-ed25519 +options key-comment: me@laptop"
    assert checks.nft_has_rules("table inet f {\n chain input {\n  type filter hook input priority 0;\n  tcp dport 22 accept\n }\n}")
    assert not checks.nft_has_rules("table inet f {\n}")


def test_secrets_censored():
    found = checks.find_secrets("token=%s and %s" % (GHP, HF))
    assert ("github", GHP[:8] + "…") in found and ("huggingface", HF[:7] + "…") in found
    assert GHP not in checks.censor_all("x " + GHP) and HF not in json.dumps(found)
    assert checks.find_secrets("disk-utility-symbolic-light-theme.svg task-unfinished-0123456789.png") == []


def test_secret_contents_scan():
    d = os.path.join(TMP, "scan")
    os.makedirs(d)
    with open(os.path.join(d, "config.txt"), "w") as f:
        f.write("token = " + GHP + "\n")
    os.environ["THEK_SCAN_ROOTS"] = d
    old_home = os.environ["HOME"]
    os.environ["HOME"] = os.path.join(TMP, "emptyhome")
    os.makedirs(os.environ["HOME"])
    try:
        f = checks.secret_contents()[0]
    finally:
        os.environ["HOME"] = old_home
        del os.environ["THEK_SCAN_ROOTS"]
    assert f["status"] == "CRITICAL" and len(f["evidence"]) == 1
    assert GHP not in json.dumps(f) and GHP[:8] + "…" in f["evidence"][0]


def test_redact():
    text = ("/home/alice/x alice@box.example host alice-pc 192.0.2.10 8.8.8.8 127.0.0.1:631 "
            "0.0.0.0:22 fe80::1 aa:bb:cc:dd:ee:ff key-comment: alice@alice-pc")
    r = thek.redact(text, user="alice", host="alice-pc", home="/home/alice")
    for gone in ("alice", "192.0.2.10", "8.8.8.8", "fe80::1", "aa:bb:cc:dd:ee:ff"):
        assert gone not in r, (gone, r)
    for kept in ("~/x", "<email>", "<host>", "<ip-lan>", "<ip-public>", "<mac>", "127.0.0.1:631", "0.0.0.0:22",
                 "key-comment: <key-comment>"):
        assert kept in r, (kept, r)


def _fake_report():
    findings = [checks.finding("listening_ports", "network", "WARN", "medium", "x",
                               ["tcp 192.0.2.10:22 %s %s" % (getpass.getuser(), os.uname().nodename)])]
    return thek.save_report(findings, "quick")


def test_export():
    d = _fake_report()
    out_dir = os.path.join(TMP, "output_docs")
    real_input, real_out = builtins.input, thek.OUTPUT_DOCS
    thek.OUTPUT_DOCS = out_dir
    try:
        builtins.input = lambda *a: ""  # Enter = redacted
        red = thek.export_report()
        builtins.input = lambda *a: "f"
        full = thek.export_report()
    finally:
        builtins.input, thek.OUTPUT_DOCS = real_input, real_out
    name = re.compile(r"^thek-report-\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d-(redacted|full)\.md$")
    assert name.match(os.path.basename(red)) and name.match(os.path.basename(full)), (red, full)
    assert red.endswith("-redacted.md") and full.endswith("-full.md") and os.path.dirname(red) == out_dir
    assert stat.S_IMODE(os.stat(out_dir).st_mode) == 0o700
    assert open(red).read() == open(os.path.join(d, "report.redacted.md")).read()
    assert open(full).read() == open(os.path.join(d, "report.md")).read()
    assert "192.0.2.10" not in open(red).read()
    for p in (red, full):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_summary_and_exit_code():
    f = lambda s: {"status": s}  # noqa: E731
    assert thek.exit_code([f("OK"), f("UNAVAILABLE")]) == 3
    assert thek.exit_code([f("OK"), f("ERROR")]) == 3
    assert thek.exit_code([f("OK")]) == 0
    assert thek.exit_code([f("WARN"), f("CRITICAL")]) == 2
    assert thek.summarize([f("UNAVAILABLE")])["OK"] == 0


def test_check_errors_do_not_abort():
    @checks.check("boom", "system")
    def boom():
        raise RuntimeError("x")
    r = boom()
    assert r[0]["status"] == "ERROR" and "RuntimeError" in r[0]["detail"]


def test_no_means_no():
    real_input, real_run = builtins.input, checks.run
    builtins.input = lambda *a: "n"

    def must_not_run(*a, **k):
        raise AssertionError("ran without confirmation")
    checks.run = must_not_run
    try:
        assert actions.do(["rm", "-rf", "/nothing"], root=True) is None
        assert actions.confirm("x") is False
    finally:
        builtins.input, checks.run = real_input, real_run


def test_quarantine():
    src = os.path.join(TMP, "bad.bin")
    with open(src, "w") as f:
        f.write("x")
    q = actions.quarantine([(src, "Test.Sig")])
    assert not os.path.exists(src)
    man = json.load(open(os.path.join(q, "manifest.json")))
    assert man[0]["original"] == src and os.path.exists(man[0]["quarantined"])
    assert stat.S_IMODE(os.stat(q).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(os.path.join(q, "manifest.json")).st_mode) == 0o600


def test_report_permissions():
    d = _fake_report()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(checks.data_dir()).st_mode) == 0o700
    for name in ("report.json", "report.md", "report.redacted.md"):
        assert stat.S_IMODE(os.stat(os.path.join(d, name)).st_mode) == 0o600
    assert os.path.realpath(os.path.join(checks.data_dir("reports"), "latest")) == os.path.realpath(d)


class _Ind:
    def __init__(self, value):
        self.value, self.type, self.tier, self.family, self.source = value, "domain", "t", "Fam", "src"


class FakeIocs:
    """Same contract as ZBT's IocSet.search: indicators whose value appears in the (lower-case) text."""
    def __init__(self, values):
        self.inds = [_Ind(v) for v in values]

    def search(self, text):
        return [i for i in self.inds if i.value in text]


def test_scan_journal():
    lines = ["%d noise line\n" % i for i in range(3000)]
    lines += ["%d connect to Bad.Example\n" % i for i in range(7)]
    lines += ["%d more noise\n" % i for i in range(3000)]
    hits, n = actions.scan_journal(FakeIocs(["bad.example", "never.seen"]), iter(lines), block_chars=20000)
    assert n == len(lines)
    assert list(hits) == ["bad.example"]
    assert hits["bad.example"]["count"] == 7 and len(hits["bad.example"]["lines"]) == 5
    assert hits["bad.example"]["family"] == "Fam"


def test_journal_scan_no_files():
    """The journal is streamed: scan_journal never opens a file."""
    tree = ast.parse(open(os.path.join(HERE, "actions.py")).read())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "scan_journal")
    calls = {c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    assert "open" not in calls, calls


def test_zbt_iocs_optional():
    real = actions.zbt_dir
    actions.zbt_dir = lambda: os.path.join(TMP, "no-zbt-here")
    try:
        assert actions.zbt_iocs() == (None, 0)
    finally:
        actions.zbt_dir = real


def test_vendor_and_output_inside_repo():
    for path in (actions.zbt_dir(), actions.ZBT_CACHE, thek.OUTPUT_DOCS):
        assert path.startswith(HERE + os.sep), path
    ignored = open(os.path.join(HERE, ".gitignore")).read().split()
    assert "vendor/" in ignored and "output_docs/" in ignored


class _Patch:
    """Swap attributes for the duration of a with-block."""
    def __init__(self, *triples):
        self.triples, self.saved = triples, []

    def __enter__(self):
        for obj, name, value in self.triples:
            self.saved.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

    def __exit__(self, *a):
        for obj, name, value in reversed(self.saved):
            setattr(obj, name, value)


def test_total_review_single_report():
    out_dir = os.path.join(TMP, "total_out")
    reports = checks.data_dir("reports")
    before = set(os.listdir(reports))
    ok = checks.finding("mac", "system", "OK")
    warn = checks.finding("sshd", "ssh", "WARN", "medium")
    journal = checks.finding("journal_iocs", "spyware", "OK")
    with _Patch((checks, "run_checks", lambda funcs: [ok]),
                (checks, "full_audit", lambda quick: ([warn], True)),
                (thek, "_journal_findings", lambda: [journal]),
                (actions, "zbt_script", lambda: None),
                (actions, "zbt_install", lambda: False),
                (actions, "missing_packages", lambda fam: ([], [])),
                (thek, "OUTPUT_DOCS", out_dir),
                (builtins, "input", lambda *a: "n")):
        d = thek.total_review()
    new = set(os.listdir(reports)) - before - {"latest"}
    assert len(new) == 1 and os.path.basename(d) in new, new
    rep = json.load(open(os.path.join(d, "report.json")))
    assert rep["kind"] == "total" and rep["flags"]["root_ran"] is True
    assert [f["id"] for f in rep["findings"]] == ["mac", "sshd", "journal_iocs"]
    assert not os.path.exists(out_dir)  # "n" = no export


def test_update_external_no_means_no():
    calls = []
    zdir = os.path.join(TMP, "fakezbt")
    os.makedirs(os.path.join(zdir, ".git"), exist_ok=True)

    def fake_run(argv, root=False, timeout=600, capture=True):
        calls.append(argv)
        if "rev-parse" in argv:
            return 0, ("a" * 40 if argv[-1] == "HEAD" else "b" * 40) + "\n"
        if "log" in argv:
            return 0, "bbbbbbb new upstream commit\n"
        if "diff" in argv:
            return 0, " 1 file changed, 1 insertion(+)\n"
        return 0, ""

    answers = iter(["s", "n"])  # yes to fetch, NO to checkout
    with _Patch((checks, "run", fake_run), (actions, "zbt_dir", lambda: zdir),
                (actions, "zbt_script", lambda: None), (builtins, "input", lambda *a: next(answers))):
        actions.update_external()
    assert any("fetch" in c for c in calls)
    assert not any("checkout" in c for c in calls), calls

def test_actions_catalog():
    assert set(actions.ACTION_IDS) == set(actions.ACTIONS)


def _sources():
    return [os.path.join(HERE, f) for f in os.listdir(HERE) if f.endswith(".py")]


def _imports(path):
    names = set()
    for node in ast.walk(ast.parse(open(path).read())):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    return names


def test_no_network_anywhere():
    """THEK itself never opens a connection: no network module in any file."""
    for path in _sources():
        bad = _imports(path) & {"socket", "urllib", "http", "requests", "ssl"}
        assert not bad, (path, bad)
    assert "actions" not in _imports(os.path.join(HERE, "checks.py"))


def test_no_shell_true():
    for path in _sources():
        for node in ast.walk(ast.parse(open(path).read())):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                raise AssertionError("shell= in " + path)


def _tracked_files():
    try:
        out = subprocess.run(["git", "-C", HERE, "ls-files"], capture_output=True, text=True, check=True).stdout.split()
        if out:
            return [os.path.join(HERE, f) for f in out]
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for dirpath, dirnames, filenames in os.walk(HERE):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        found += [os.path.join(dirpath, f) for f in filenames]
    return found


def test_repo_has_no_personal_data():
    user, host, home = getpass.getuser(), os.uname().nodename, os.path.expanduser("~")
    generic = {"root", "user", "runner", "admin", "localhost", "/root", "/home/user"}
    needles = [n for n in (user, host, home) if n and n not in generic and len(n) >= 4]
    for path in _tracked_files():
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for n in needles:
            assert n not in text, "%s contains personal data (%r)" % (path, n)
        assert not checks.find_secrets(text), "%s contains a secret" % path


def test_banner():
    big = thek.banner(100)
    assert "████████╗██╗  ██╗███████╗██╗  ██╗" in big and "T U X" in big
    for name in ("ClamAV", "rkhunter", "chkrootkit", "Lynis", "Zero Breach Toolkit"):
        assert name in big
    assert "\x1b" not in big and "Check · Clean · Protect · You decide" in big and "telemetry" not in big
    small = thek.banner(30)
    assert "THEK" in small and "███" not in small and "Tux Health Easy Kit" in small
    assert "\x1b[38;2;" in thek.banner(100, "rgb") and "\x1b[1;34m" in thek.banner(100, "basic")


def test_menu_keys():
    assert [key for key, _, _, _ in thek.MENU()] == [str(i) for i in range(1, 7)]


def test_menu_texts():
    """Every option has a short label and an explanation, in both languages."""
    for lang in ("es", "en"):
        keys = i18n.STRINGS[lang]
        items = {k[5:] for k in keys if k.startswith("item.")}
        infos = {k[5:] for k in keys if k.startswith("info.")}
        assert items == infos and len(items) == 27, (lang, items ^ infos)


def test_leaf_needs_yes():
    ran = []
    _, run = thek.leaf("quick", lambda: ran.append(1))
    real = builtins.input
    try:
        builtins.input = lambda prompt="": "n"
        run()
        assert ran == []
        builtins.input = lambda prompt="": "y"
        run()
        assert ran == [1]
    finally:
        builtins.input = real


if __name__ == "__main__":
    import shutil
    try:
        for name, fn in list(globals().items()):
            if name.startswith("test_"):
                fn()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok")
