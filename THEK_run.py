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


def total_review():
    """Everything in one pass: questions first, then it runs on its own and leaves one report."""
    print("\n" + t("total.prep"))
    if not actions.zbt_script():
        actions.zbt_install()
    if actions.zbt_script():
        iocs, n_downloaded = actions.zbt_iocs()
        if iocs is None or n_downloaded == 0 or iocs.is_stale(30):
            actions.zbt_update()
    if actions.missing_packages(checks.platform()["family"])[0]:
        actions.install()
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
        print(t("d.missing_tool", tool="clamscan") + " → " + t("m.install"))
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
    submenu(t("m.clamav"), [
        (t("clam.update"), lambda: actions.do(["freshclam"], root=True)),
        (t("clam.downloads"), lambda: clam_scan(_downloads())),
        (t("clam.home"), lambda: clam_scan(os.path.expanduser("~"))),
        (t("clam.path"), clam_path),
        (t("clam.all"), lambda: clam_scan("/", root=True)),
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
    submenu(t("m.zbt"), [
        (t("zbt.standard"), lambda: zbt_scan([])),
        (t("zbt.full"), lambda: zbt_scan(["--scan-type", "full"])),
        (t("zbt.journal"), journal_ioc_scan),
    ])


# ---------------------------------------------------------------- menu

def latest_report_dir():
    path = os.path.join(checks.data_dir("reports"), "latest")
    return os.path.realpath(path) if os.path.exists(path) else None


def header():
    p = checks.platform()
    last = latest_report_dir()
    last = os.path.basename(last) if last else t("menu.none")
    print()
    print(color("THEK", "1;36") + " · %s %s · %s: %s" % (p["id"], p["version"], t("menu.last"), last))


def submenu(title, items):
    """items: list of (label, fn). Loops until 0 / EOF."""
    while True:
        print("\n" + color(title, "1"))
        for i, (label, _) in enumerate(items, 1):
            print("  %2d  %s" % (i, label))
        print("   0  " + t("menu.back"))
        choice = ask("> ")
        if choice is None or choice.strip() == "0":
            return
        if choice.strip().isdigit() and 1 <= int(choice) <= len(items):
            try:
                items[int(choice) - 1][1]()
            except KeyboardInterrupt:
                print("\n" + t("menu.interrupted"))


def main_menu():
    handlers = MENU()
    while True:
        header()
        for key, label, _ in handlers:
            print("  %2s  %s" % (key, label))
        print("   0  " + t("menu.exit"))
        try:
            choice = ask("> ")
        except KeyboardInterrupt:
            print()
            return 0
        if choice is None or choice.strip() == "0":
            return 0
        for key, _, fn in handlers:
            if choice.strip() == key:
                try:
                    fn()
                except KeyboardInterrupt:
                    print("\n" + t("menu.interrupted"))


def MENU():
    return [
        ("1", t("m.total"), total_review),
        ("2", t("m.quick"), lambda: audit("quick")),
        ("3", t("m.full"), lambda: audit("full")),
        ("4", t("m.clamav"), clam_menu),
        ("5", t("m.zbt"), zbt_menu),
        ("6", t("m.secrets"), secrets_scan),
        ("7", t("m.clean"), lambda: submenu(t("m.clean"), [
            (t("a." + a), actions.ACTIONS[a]) for a in
            ("pkg_cache", "autoremove", "flatpak_unused", "journal_vacuum", "trash", "thumbnails", "coredumps")])),
        ("8", t("m.harden"), lambda: submenu(t("m.harden"), [
            (t("a." + a), actions.ACTIONS[a]) for a in ("firewall", "freshclam_auto", "auto_updates")])),
        ("9", t("m.update"), actions.upgrade),
        ("10", t("m.install"), actions.install),
        ("11", t("m.external"), actions.update_external),
        ("12", t("m.llm"), export_report),
        ("13", t("m.view"), view_report),
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
