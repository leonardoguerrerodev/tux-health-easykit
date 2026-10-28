#!/usr/bin/env python3
"""THEK: terminal menu to audit, scan, clean and harden a Linux machine."""
import argparse
import getpass
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time

import actions
import checks
from i18n import lang, set_lang, t


def color(text, code):
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def ask(prompt):
    """input() that returns None on EOF (piped input ran out)."""
    try:
        return input(prompt)
    except EOFError:
        return None


# ---------------------------------------------------------------- banner

GLYPHS = {  # 'ANSI Shadow' letters, as in Zero Breach Toolkit's banner
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "K": ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
}
RAMP = [(25, 70, 170), (35, 95, 205), (45, 125, 230), (65, 150, 245), (95, 175, 255), (135, 200, 255)]
CREDITS = "ClamAV · rkhunter · chkrootkit · Lynis · Zero Breach Toolkit"


def color_mode():
    """'rgb', 'basic' or None: what this terminal can show."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return None
    return "rgb" if os.environ.get("COLORTERM") in ("truecolor", "24bit") else "basic"


def banner(width, mode=None):
    """The title screen as text (pure, so tests can check it). mode: 'rgb', 'basic' or None."""
    def paint(text, rgb, basic="1;34"):
        code = "38;2;%d;%d;%d" % rgb if mode == "rgb" and rgb else basic
        return "\033[%sm%s\033[0m" % (code, text) if mode else text

    def wrapped(text, rgb, basic):
        return [pad + paint(line, rgb, basic) for line in textwrap.wrap(text, max(20, width - 4))]

    pad = "  "
    out = [""]
    if width < 40:
        out.append(pad + paint("THEK", RAMP[3]))
    else:
        out += [pad + paint("".join(GLYPHS[c][i] for c in "THEK"), RAMP[i]) for i in range(6)]
    out.append("")
    out.append(pad + paint("T U X  ·  H E A L T H  ·  E A S Y  ·  K I T" if width >= 50 else "Tux Health Easy Kit",
                           RAMP[5], "34"))
    out += wrapped(t("banner.concepts"), RAMP[4], "34")
    out.append(pad + paint("─" * min(width - 4, 64), RAMP[1], "34"))
    out += wrapped(t("banner.credits") + " " + CREDITS, None, "2")
    return "\n".join(out)


def show_banner():
    if sys.stdout.isatty():
        print(banner(shutil.get_terminal_size((80, 24)).columns, color_mode()))


# ---------------------------------------------------------------- doctor

def doctor():
    p = checks.platform()
    print("family: " + p["family"])
    print("%s: %s %s" % (t("doctor.distro"), p["id"], p["version"]))
    print("%s: %s" % (t("doctor.kernel"), p["kernel"]))
    print("%s: %s" % (t("doctor.python"), sys.version.split()[0]))
    prefix = checks.elevate_prefix()
    if prefix is None:
        elev = t("doctor.elevate_none")
    else:
        elev = prefix[0] if prefix else t("doctor.elevate_root")
    print("%s: %s" % (t("doctor.elevate"), elev))
    print("%s: %s" % (t("doctor.data"), checks.data_dir()))
    print(t("doctor.tools") + ":")
    for name, path in checks.tools().items():
        print("  %-14s %s" % (name, path or "- " + t("doctor.missing")))


# ---------------------------------------------------------------- report

STATUS_ORDER = ["CRITICAL", "WARN", "UNAVAILABLE", "ERROR", "OK"]


def summarize(findings):
    counts = {s: 0 for s in STATUS_ORDER}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


def exit_code(findings):
    """0 clean, 2 CRITICAL, 3 WARN / UNAVAILABLE / ERROR (a gap is never clean)."""
    s = summarize(findings)
    if s["CRITICAL"]:
        return 2
    if s["WARN"] or s["UNAVAILABLE"] or s["ERROR"]:
        return 3
    return 0


_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _ip_label(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified:
        return text  # 127.0.0.1 / 0.0.0.0 / :: identify nobody and matter for the analysis
    return "<ip-lan>" if (ip.is_private or ip.is_link_local) else "<ip-public>"


def redact(text, user=None, host=None, home=None):
    """Remove what identifies this person or machine: user, host, home path, IPs, MACs, emails, key comments."""
    user = user or getpass.getuser()
    host = host or os.uname().nodename
    home = home or os.path.expanduser("~")
    text = text.replace(home, "~")
    text = re.sub(r"key-comment: .*", "key-comment: <key-comment>", text)
    text = _EMAIL.sub("<email>", text)
    text = _MAC.sub("<mac>", text)
    text = _IPV4.sub(lambda m: _ip_label(m.group(0)) or m.group(0), text)
    text = _IPV6.sub(lambda m: _ip_label(m.group(0)) or m.group(0), text)
    for word, label in ((host, "<host>"), (user, "<user>")):
        if word:
            text = re.sub(r"(?<![\w-])%s(?![\w-])" % re.escape(word), label, text)
    return checks.censor_all(text)


def render_md(rep):
    """The report is also a self-contained prompt for any LLM."""
    L = [t("r.title", kind=t("r.kind_" + rep["kind"])), "", "## " + t("r.instructions_h"), "", t("r.instructions"), ""]
    p = rep["platform"]
    L += ["## " + t("r.context_h"), "",
          "- %s: %s %s (%s)" % (t("r.distro"), p["id"], p["version"], p["family"]),
          "- kernel: " + p["kernel"],
          "- %s: %s" % (t("r.date"), rep["created"]),
          "- root_ran: %s" % rep["flags"]["root_ran"],
          "- offline: %s" % rep["flags"]["offline"], ""]
    for f in rep["findings"]:
        if f["status"] == "OK" and f["evidence"]:
            L += ["### " + f["title"], f["detail"], "", "```"] + f["evidence"] + ["```", ""]
    L += ["## " + t("r.summary_h"), ""]
    L += ["- %s: %d" % (s, n) for s, n in rep["summary"].items()] + [""]
    L += ["## " + t("r.findings_h"), ""]
    for status in STATUS_ORDER[:-1]:
        for f in [x for x in rep["findings"] if x["status"] == status]:
            L += ["### [%s · %s] %s" % (status, f["severity"], f["title"]), "", "- id: `%s`" % f["id"]]
            if f["detail"]:
                L.append("- %s: %s" % (t("r.detail"), f["detail"]))
            if f["suggestion"]:
                L.append("- %s: %s" % (t("r.suggestion"), f["suggestion"]))
            if f["action"]:
                L.append("- %s: `%s`" % (t("r.action"), f["action"]))
            if f["evidence"]:
                L += ["", "```"] + f["evidence"] + ["```"]
            L.append("")
    L += ["## " + t("r.actions_h"), ""]
    L += ["- `%s`: %s" % (a, t("a." + a)) for a in actions.ACTION_IDS] + [""]
    return "\n".join(L)


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def new_report_dir():
    """A fresh folder per report; two reports in the same second get -2, -3… instead of overwriting."""
    base, stamp = checks.data_dir("reports"), time.strftime("%Y-%m-%dT%H-%M-%S")
    name, n = stamp, 1
    while os.path.exists(os.path.join(base, name)):
        n += 1
        name = "%s-%d" % (stamp, n)
    return checks.data_dir("reports", name)


def save_report(findings, kind, root_ran=False, d=None):
    d = d or new_report_dir()
    stamp = os.path.basename(d)
    rep = {"created": stamp, "kind": kind, "lang": lang(), "platform": checks.platform(),
           "flags": {"root_ran": root_ran, "offline": True},
           "summary": summarize(findings), "findings": findings}
    _write_private(os.path.join(d, "report.json"), json.dumps(rep, indent=1, ensure_ascii=False))
    md = render_md(rep)
    _write_private(os.path.join(d, "report.md"), md)
    _write_private(os.path.join(d, "report.redacted.md"), redact(md))
    link = os.path.join(checks.data_dir("reports"), "latest")
    tmp = link + ".tmp"
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(stamp, tmp)
    os.replace(tmp, link)
    return d


def print_summary(findings, report_dir):
    s = summarize(findings)
    print()
    print("  " + "  ".join("%s %d" % (k, v) for k, v in s.items()))
    for status, code in (("CRITICAL", "1;31"), ("WARN", "33"), ("UNAVAILABLE", "2"), ("ERROR", "35")):
        for f in [x for x in findings if x["status"] == status]:
            print("  " + color("%-11s" % status, code) + " " + f["title"] + (" — " + f["detail"] if f["detail"] else ""))
    print("\n" + t("r.saved") + " " + os.path.join(report_dir, "report.md"))


def collect_audit(kind):
    findings = checks.run_checks(checks.QUICK)
    root_ran = False
    if kind == "full":
        extra, root_ran = checks.full_audit(findings)
        findings += extra
    return findings, root_ran


def audit(kind):
    findings, root_ran = collect_audit(kind)
    d = save_report(findings, kind, root_ran)
    print_summary(findings, d)
    return exit_code(findings)


def view_report():
    d = latest_report_dir()
    if not d:
        print(t("r.none"))
        return
    path = os.path.join(d, "report.md")
    if sys.stdout.isatty() and shutil.which("less"):
        subprocess.call(["less", "-R", path])
        return DONE  # closing less is enough, no extra Enter
    else:
        with open(path, encoding="utf-8") as f:
            print(f.read())


# ---------------------------------------------------------------- export for the user's own AI

OUTPUT_DOCS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output_docs")  # ignored by git


def export_report(full=None):
    """Copy the last report to output_docs/ for the user to hand to an AI they trust. THEK never sends it.
    full=None asks; True/False is an answer given earlier (total review)."""
    d = latest_report_dir()
    if not d:
        print(t("r.none"))
        return None
    if full is None:
        print("\n" + t("export.warning"))
        full = (ask(t("export.which") + " ") or "").strip().lower() in ("c", "completo", "f", "full")
    with open(os.path.join(d, "report.md" if full else "report.redacted.md"), encoding="utf-8") as f:
        text = f.read()
    os.makedirs(OUTPUT_DOCS, mode=0o700, exist_ok=True)
    os.chmod(OUTPUT_DOCS, 0o700)
    name = "%s-%s-%s.md" % (t("export.name"), time.strftime("%Y-%m-%d_%H-%M-%S"),
                            t("export.full" if full else "export.redacted"))
    path = os.path.join(OUTPUT_DOCS, name)
    _write_private(path, text)
    print("\n" + t("export.done", path=path, cd="cd " + shlex.quote(OUTPUT_DOCS)))
    return path


def _iocs_state():
    if not actions.zbt_script():
        return False, t("prep.missing")
    iocs, n = actions.zbt_iocs()
    if iocs is None or n == 0:
        return False, t("prep.missing")
    if iocs.is_stale(30):
        return False, t("prep.iocs_old", n=len(iocs))
    return True, t("prep.iocs_n", n=len(iocs))


def _clam_state():
    f = checks.clamav_signatures()[0]
    return f["status"] == "OK", f["detail"] or t("prep.missing")


def readiness():
    """What THEK needs, in the order prepare() fixes it: [(key, ok, detail)]."""
    pkgs, _ = actions.missing_packages(checks.platform()["family"])
    have_zbt = bool(actions.zbt_script())
    return [("tools", not pkgs, ", ".join(pkgs) or t("prep.ok")),
            ("zbt", have_zbt, t("prep.ok") if have_zbt else t("prep.missing")),
            ("iocs",) + _iocs_state(),
            ("clam",) + _clam_state()]


def show_readiness(items):
    for key, ok, detail in items:
        print("  %s %-26s %s" % (color("✓", "32") if ok else color("✗", "33"), t("prep." + key), color(detail, "2")))


def prepare(upstream=True):
    """Shows what is there and what is missing, then fixes only what is needed, each step with its own yes.
    Order matters: installing brings git and ClamAV, which the next steps need."""
    print()
    show_readiness(readiness())
    if actions.missing_packages(checks.platform()["family"])[0]:
        actions.install()
    if upstream:
        actions.update_external(refresh_iocs=False)  # downloads ZBT if missing, otherwise looks for a new version
    elif not actions.zbt_script():
        actions.zbt_install()
    if actions.zbt_script() and not _iocs_state()[0]:
        actions.zbt_update()
    if shutil.which("freshclam") and not _clam_state()[0]:
        actions.freshclam()
    items = readiness()
    print()
    show_readiness(items)
    print("\n" + t("prep.ready" if all(ok for _, ok, _ in items) else "prep.pending"))


def total_review():
    """Everything in one pass: questions first, then it runs on its own and leaves one report."""
    print("\n" + t("total.prep"))
    prepare(upstream=False)
    zbt = bool(actions.zbt_script()) and (ask(t("total.zbt_scan") + " ") or "").strip() in ("s", "S", "y", "Y")
    print("\n" + t("export.warning"))
    answer = (ask(t("total.export") + " ") or "").strip().lower()
    export = None if answer in ("n", "no") else answer in ("c", "completo", "f", "full")
    print("\n" + t("total.unattended"))
    d = new_report_dir()
    findings, root_ran = collect_audit("full")
    findings += _journal_findings()
    if zbt:
        findings.append(actions.zbt_finding(actions.zbt_run([], d)))
    save_report(findings, "total", root_ran, d)
    print_summary(findings, d)
    if export is not None:
        export_report(full=export)
    return d


# ---------------------------------------------------------------- ClamAV / ZBT menus

def _downloads():
    code, out = checks.run(["xdg-user-dir", "DOWNLOAD"], timeout=10)
    path = out.strip() if code == 0 else ""
    return path if os.path.isdir(path) else os.path.expanduser("~/Downloads")


def clam_scan(target, root=False):
    if not shutil.which("clamscan"):
        print(t("d.missing_tool", tool="clamscan") + " → " + t("menu.option1"))
        return
    hits, _ = actions.clamscan(target, root)
    findings = actions.clam_findings(hits)
    d = save_report(findings, "clamav")
    print_summary(findings, d)
    if hits:
        print("\n" + t("clam.quarantine", n=len(hits)))
        dest = os.path.join(checks.data_dir("quarantine"), "<%s>" % t("clam.date"))
        if actions.confirm(actions.shown(["mv", "--"] + [p for p, _ in hits] + [dest])):
            print(t("clam.moved") + " " + actions.quarantine(hits))


def clam_path():
    path = ask(t("clam.ask_path") + " ")
    if path and os.path.exists(os.path.expanduser(path.strip())):
        clam_scan(os.path.expanduser(path.strip()))
    else:
        print(t("clam.no_path"))


def clam_menu():
    return submenu(t("m.clamav"), [
        leaf("clam_update", lambda: actions.do(["freshclam"], root=True), asks=True),
        leaf("clam_downloads", lambda: clam_scan(_downloads())),
        leaf("clam_home", lambda: clam_scan(os.path.expanduser("~"))),
        leaf("clam_path", clam_path),
        leaf("clam_all", lambda: clam_scan("/", root=True)),
    ])


def secrets_scan():
    print(t("sec.scanning", roots=", ".join(checks.scan_roots())))
    findings = checks.secret_names() + checks.secret_contents()
    d = save_report(findings, "secrets")
    print_summary(findings, d)


def zbt_scan(extra):
    d = new_report_dir()
    code = actions.zbt_run(extra, d)
    findings = [actions.zbt_finding(code)]
    save_report(findings, "zbt", d=d)
    print_summary(findings, d)


JOURNAL_GROUPS = {"wheel", "adm", "systemd-journal"}


def _can_read_journal():
    if os.geteuid() == 0:
        return True
    import grp
    names = set()
    for gid in os.getgroups():
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return bool(names & JOURNAL_GROUPS)


def _journal_findings():
    f = checks.finding
    if not shutil.which("journalctl"):
        return [f("journal_iocs", "spyware", "UNAVAILABLE", "medium", t("d.missing_tool", tool="journalctl"))]
    iocs, n_downloaded = actions.zbt_iocs()
    if iocs is None:
        return [f("journal_iocs", "spyware", "UNAVAILABLE", "medium", t("d.zbt_missing"))]
    argv = ["journalctl", "--no-pager", "-q", "-o", "short-iso"]
    prefix = []
    if not _can_read_journal():
        prefix = checks.elevate_prefix()
        if prefix is None or not actions.confirm(actions.shown(argv, root=True)):
            return [f("journal_iocs", "spyware", "UNAVAILABLE", "medium", t("d.root_denied"))]
    print(t("zbt.journal_wait", n=len(iocs)))
    # streamed: the journal is never copied to disk; only matching lines end up in the report
    proc = subprocess.Popen(prefix + argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            errors="replace", env=dict(os.environ, LC_ALL="C"))
    hits, n_lines = actions.scan_journal(iocs, proc.stdout)
    code = proc.wait()
    res = []
    if n_lines == 0 and code != 0:
        res.append(f("journal_iocs", "spyware", "UNAVAILABLE", "medium", "journalctl exit %s" % code))
    elif hits:
        ev = []
        for value, h in hits.items():
            ev.append("%s [%s, %s, %s] ×%d" % (value, h["type"], h["family"] or h["tier"], h["source"], h["count"]))
            ev += ["  " + line for line in h["lines"]]
        res.append(f("journal_iocs", "spyware", "WARN", "high", t("d.journal_hits", n=len(hits), lines=n_lines), ev))
    else:
        res.append(f("journal_iocs", "spyware", "OK", detail=t("d.journal_ok", lines=n_lines, n=len(iocs))))
    if n_downloaded == 0 or iocs.is_stale(30):
        res.append(f("journal_iocs_stale", "spyware", "UNAVAILABLE", "medium"))
    return res


def journal_ioc_scan():
    findings = _journal_findings()
    d = save_report(findings, "journal")
    print_summary(findings, d)


def zbt_menu():
    if not actions.zbt_script() and not actions.zbt_install():
        return
    return submenu(t("m.zbt"), [
        leaf("zbt_standard", lambda: zbt_scan([])),
        leaf("zbt_full", lambda: zbt_scan(["--scan-type", "full"])),
        leaf("zbt_journal", journal_ioc_scan),
    ])


# ---------------------------------------------------------------- menu

def latest_report_dir():
    path = os.path.join(checks.data_dir("reports"), "latest")
    return os.path.realpath(path) if os.path.exists(path) else None


def status_line():
    """Distro, last report with its counts, and a hint when tools are missing."""
    p = checks.platform()
    parts = ["%s %s" % (p["id"], p["version"])]
    last = latest_report_dir()
    if not last:
        parts.append("%s: %s" % (t("menu.last"), t("menu.none")))
    else:
        stamp = os.path.basename(last)
        parts.append("%s: %s %s" % (t("menu.last"), stamp[:10], stamp[11:16].replace("-", ":")))
        try:
            with open(os.path.join(last, "report.json"), encoding="utf-8") as f:
                s = json.load(f)["summary"]
            if s["CRITICAL"]:
                parts.append(color(t("menu.critical", n=s["CRITICAL"]), "1;31"))
            if s["WARN"]:
                parts.append(color(t("menu.warn", n=s["WARN"]), "33"))
            if not (s["CRITICAL"] or s["WARN"]):
                parts.append(color(t("menu.allok"), "32"))
        except (OSError, ValueError, KeyError):
            pass
    print("  " + " · ".join(parts))
    if actions.missing_packages(p["family"])[0] or not actions.zbt_script():
        print("  " + color(t("menu.need_prepare"), "33"))


def yes(prompt):
    return (ask(prompt + " ") or "").strip() in ("s", "S", "y", "Y")


def leaf(id, fn, asks=False):
    """A menu option that first says what it does. asks=True: fn already asks with the exact command,
    so the user answers one yes, not two."""
    def run():
        print("\n  " + color(t("item." + id), "1;34"))
        lines = t("info." + id).split("\n")
        for line in lines[:-1]:
            print("  " + line)
        print("  " + color(lines[-1], "2"))
        if not asks and not yes("\n" + t("menu.go")):
            return BACK  # said no: stay in this menu, no extra Enter
        return fn()
    return t("item." + id), run


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty()


def pause():
    if interactive():
        ask(color(t("menu.enter"), "2"))


def clear():
    if interactive():
        print("\033[H\033[2J", end="")  # keeps the scrollback


BACK = object()  # went back or said no: stay in the menu you were in
DONE = object()  # something ran and the user has seen it: straight to the main menu, no 0 needed


def run_item(fn):
    try:
        r = fn()
        if r is BACK or r is DONE:
            return r
    except KeyboardInterrupt:
        print("\n" + t("menu.interrupted"))
    pause()
    return DONE


def invalid(choice):
    print(color(t("menu.invalid", choice=choice), "33"))
    pause()


def submenu(title, items):
    """items: list of (label, fn). Loops until 0 / EOF."""
    while True:
        clear()
        print("\n  " + color(title, "1;34"))
        for i, (text, _) in enumerate(items, 1):
            print("  %s  %s" % (color("%2d" % i, "1"), text))
        print("  %s  %s" % (color(" 0", "1"), t("menu.back")))
        choice = ask("\n" + t("menu.choose", last=len(items)) + " ")
        if choice is None or choice.strip() == "0":
            return BACK
        c = choice.strip()
        if c.isdigit() and 1 <= int(c) <= len(items):
            if run_item(items[int(c) - 1][1]) is DONE:
                return DONE
        elif c:
            invalid(c)


def main_menu():
    handlers = MENU()
    fns = {key: fn for key, _, _, fn in handlers}
    while True:
        clear()
        show_banner()
        print()
        status_line()
        print()
        width = max(len(text) for _, text, _, _ in handlers) + 2
        for key, text, hint, _ in handlers:
            hint = color(hint, "1;33") if hint == t("menu.recommended") else color(hint, "2")
            print("  %s  %s%s" % (color("%2s" % key, "1"), text.ljust(width), hint))
        print("\n  %s  %s" % (color(" 0", "1"), t("menu.exit")))
        try:
            choice = ask("\n" + t("menu.choose", last=handlers[-1][0]) + " ")
        except KeyboardInterrupt:
            choice = None
            print()
        if choice is None or choice.strip() == "0":
            print(t("menu.bye"))
            return 0
        c = choice.strip()
        if c in fns:
            run_item(fns[c])
        elif c:
            invalid(c)


def check_menu():
    return submenu(t("m.check"), [
        leaf("quick", lambda: audit("quick")),
        leaf("full", lambda: audit("full")),
        (t("m.clamav") + " ›", clam_menu),
        (t("m.zbt") + " ›", zbt_menu),
        leaf("secrets", secrets_scan),
    ])


def actions_menu(title, ids):
    return submenu(title, [leaf(a, actions.ACTIONS[a], asks=True) for a in ids])


def MENU():
    """(key, label, hint, fn). The README refers to options 1 and 2."""
    return [
        ("1", t("m.prepare"), t("hint.prepare"), leaf("prepare", prepare, asks=True)[1]),
        ("2", t("m.total"), t("menu.recommended"), leaf("total", total_review)[1]),
        ("3", t("m.check") + " ›", t("hint.check"), check_menu),
        ("4", t("m.clean") + " ›", t("hint.clean"), lambda: actions_menu(t("m.clean"), (
            "pkg_cache", "autoremove", "flatpak_unused", "journal_vacuum", "trash", "thumbnails", "coredumps"))),
        ("5", t("m.protect") + " ›", t("hint.protect"), lambda: actions_menu(t("m.protect"), (
            "firewall", "freshclam_auto", "auto_updates", "upgrade"))),
        ("6", t("m.reports") + " ›", t("hint.reports"), lambda: submenu(t("m.reports"), [
            leaf("view", view_report), leaf("export", export_report, asks=True)])),
    ]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="THEK_run.py")
    ap.add_argument("--doctor", action="store_true")
    ap.add_argument("--audit", choices=["quick", "full"])
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--lang", choices=["es", "en"])
    args = ap.parse_args(argv)
    if args.lang:
        set_lang(args.lang)
    if args.doctor:
        doctor()
        return 0
    if args.audit:
        return audit(args.audit)
    if args.install:
        actions.install()
        return 0
    return main_menu()


if __name__ == "__main__":
    sys.exit(main())
