"""Everything that changes the system. Each action shows the exact command and asks first."""
import hashlib
import json
import os
import shlex
import shutil
import sys
import time

import checks
from i18n import t

# Ids the report offers to the LLM and that findings point to (finding["action"]).
ACTION_IDS = ["install", "upgrade", "freshclam", "freshclam_auto", "firewall", "auto_updates",
              "pkg_cache", "autoremove", "flatpak_unused", "journal_vacuum", "trash",
              "thumbnails", "coredumps"]


def confirm(cmd_str):
    print("\n  $ " + cmd_str)
    try:
        ans = input(t("confirm") + " ")
    except EOFError:
        return False
    return ans.strip() in ("s", "S", "y", "Y")


def shown(argv, root=False):
    prefix = (checks.elevate_prefix() or []) if root else []
    return " ".join(shlex.quote(a) for a in prefix + list(argv))


def do(argv, root=False, capture=False):
    """Show the exact command, ask, run. Returns (code, output) or None when the user said no."""
    if not confirm(shown(argv, root)):
        print(t("skipped"))
        return None
    return checks.run(argv, root=root, timeout=None, capture=capture)


def _family():
    p = checks.platform()
    return p["family"], checks.family_cmds(p["family"])


def _size(path):
    code, out = checks.run(["du", "-sh", path], timeout=120)
    return out.split()[0] if code == 0 and out.split() else "?"


# ---------------------------------------------------------------- install / update

def missing_packages(family):
    """(packages to install, tools with no package in the official repos)."""
    pkgs, nopkg = [], []
    for tool in checks.WANTED:
        if family not in checks.PACKAGES.get(tool, {}) or checks.have(tool):
            continue
        pkg = checks.PACKAGES[tool][family]
        if pkg is None:
            nopkg.append(tool)
        elif pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs, nopkg


def install():
    fam, cmds = _family()
    if not cmds:
        print(t("d.unsupported"))
        return
    pkgs, nopkg = missing_packages(fam)
    for tool in nopkg:
        print(t("inst.nopkg", tool=tool, hint=checks.MISSING_HINT.get(fam, "")))
    if not pkgs:
        print(t("inst.none"))
        return
    if checks.platform()["id"] in checks.EPEL_IDS:
        print(t("inst.epel"))
    do(cmds["install"] + pkgs, root=True)


def _install_one(tool):
    fam, cmds = _family()
    pkg = checks.PACKAGES.get(tool, {}).get(fam)
    if checks.have(tool):
        return True
    if not pkg or not cmds:
        print(t("inst.nopkg", tool=tool, hint=checks.MISSING_HINT.get(fam, "")))
        return False
    return do(cmds["install"] + [pkg], root=True) is not None and checks.have(tool)


def upgrade():
    _, cmds = _family()
    for argv in cmds.get("upgrade", []):
        # nobara-sync elevates itself with sudo; the rest need root from us
        if do(argv, root=argv[0] != "nobara-sync") is None:
            return
    if shutil.which("flatpak"):
        do(["flatpak", "update"])
    if shutil.which("fwupdmgr"):
        do(["fwupdmgr", "refresh"])
        do(["fwupdmgr", "update"])


# ---------------------------------------------------------------- hardening

def freshclam():
    do(["freshclam"], root=True)


def _unit_exists(unit):
    return any(os.path.exists(os.path.join(d, unit)) for d in
               ("/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"))


def freshclam_auto():
    unit = next((u for u in checks.FRESHCLAM_UNITS if _unit_exists(u)), None)
    if unit is None:
        print(t("harden.no_unit", unit="freshclam"))
        return
    do(["systemctl", "enable", "--now", unit], root=True)


def firewall():
    fam, _ = _family()
    if fam == "debian":
        if not _install_one("ufw"):
            return
        sshd_on = any(checks.run(["systemctl", "is-active", u], timeout=20)[1].strip() == "active" for u in ("ssh", "sshd"))
        if sshd_on:
            print(t("harden.ssh_first"))
            if do(["ufw", "allow", "OpenSSH"], root=True) is None:
                return
        do(["ufw", "--force", "enable"], root=True)
    elif fam in ("fedora", "suse", "arch"):
        if _install_one("firewall-cmd"):
            do(["systemctl", "enable", "--now", "firewalld"], root=True)
    else:
        print(t("d.unsupported"))


def auto_updates():
    fam, _ = _family()
    if fam == "debian":
        if _install_one("unattended-upgrade"):
            do(["dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"], root=True)
    elif fam == "fedora" and not shutil.which("nobara-sync"):
        if _install_one("dnf-automatic"):
            timer = next((u for u in ("dnf-automatic.timer", "dnf5-automatic.timer") if _unit_exists(u)), None)
            if timer:
                do(["systemctl", "enable", "--now", timer], root=True)
            else:
                print(t("harden.no_unit", unit="dnf-automatic.timer"))
    else:
        print(t("harden.no_auto"))


# ---------------------------------------------------------------- cleanup

def pkg_cache():
    _, cmds = _family()
    for argv in cmds.get("clean", []):
        do(argv, root=True)


def autoremove():
    fam, cmds = _family()
    if not cmds.get("autoremove"):
        print(t("d.unsupported"))
        return
    code, out = checks.run(cmds["autoremove_preview"], timeout=300)
    print(out.strip()[-2000:])
    if fam == "arch":
        orphans = out.split()
        if code != 0 or not orphans:
            print(t("clean.nothing"))
            return
        do(cmds["autoremove"] + orphans, root=True)
    else:
        do(cmds["autoremove"], root=True)


def flatpak_unused():
    if shutil.which("flatpak"):
        do(["flatpak", "uninstall", "--unused", "-y"])


def journal_vacuum():
    print(checks.run(["journalctl", "--disk-usage"], timeout=60)[1].strip())
    do(["journalctl", "--vacuum-time=14d"], root=True)


def _empty_dir(path):
    """Delete the contents of a folder the user owns (after showing size and asking)."""
    if not os.path.isdir(path):
        print(t("clean.nothing"))
        return
    print(t("clean.size", size=_size(path), path=path))
    if not confirm(shown(["rm", "-rf", "--", path + "/*"])):
        print(t("skipped"))
        return
    for name in os.listdir(path):
        p = os.path.join(path, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.remove(p)


def trash():
    if shutil.which("gio"):
        print(t("clean.size", size=_size(os.path.expanduser("~/.local/share/Trash")), path="~/.local/share/Trash"))
        do(["gio", "trash", "--empty"])
    else:
        _empty_dir(os.path.expanduser("~/.local/share/Trash/files"))
        _empty_dir(os.path.expanduser("~/.local/share/Trash/info"))


def thumbnails():
    _empty_dir(os.path.expanduser("~/.cache/thumbnails"))


def coredumps():
    do(["find", "/var/lib/systemd/coredump", "-mindepth", "1", "-delete"], root=True)


ACTIONS = {"install": install, "upgrade": upgrade, "freshclam": freshclam, "freshclam_auto": freshclam_auto,
           "firewall": firewall, "auto_updates": auto_updates, "pkg_cache": pkg_cache, "autoremove": autoremove,
           "flatpak_unused": flatpak_unused, "journal_vacuum": journal_vacuum, "trash": trash,
           "thumbnails": thumbnails, "coredumps": coredumps}


# ---------------------------------------------------------------- ClamAV

def parse_clamscan(text):
    """[(path, signature)] from `clamscan -i` lines 'path: Signature FOUND'."""
    out = []
    for line in text.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line[:-len(" FOUND")].rsplit(": ", 1)
            out.append((path, sig))
    return out


def clamscan(target, root=False):
    argv = ["clamscan", "-r", "-i", "--no-summary"]
    if target == "/":
        argv.append("--exclude-dir=^/(proc|sys|dev|run)")
    argv.append(target)
    print(t("clam.scanning", target=target))
    code, out = checks.run(argv, root=root, timeout=None)
    if code is None or code > 1:  # 0 clean, 1 found, 2 error
        print(out.strip()[-500:])
    return parse_clamscan(out), code


def quarantine(hits):
    """Move [(path, signature)] to the quarantine with a manifest. Never deletes anything."""
    stamp = time.strftime("%Y-%m-%dT%H-%M-%S")
    qdir = checks.data_dir("quarantine", stamp)
    manifest = []
    for i, (path, sig) in enumerate(hits):
        dest = os.path.join(qdir, "%03d-%s" % (i, os.path.basename(path)))
        try:
            with open(path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            sha = None
        if os.access(os.path.dirname(path) or ".", os.W_OK) and sha is not None:
            shutil.move(path, dest)
            os.chmod(dest, 0)
        else:  # owned by root: same move, elevated
            checks.run(["mv", "--", path, dest], root=True)
            checks.run(["chmod", "000", dest], root=True)
        manifest.append({"original": path, "quarantined": dest, "sha256": sha, "signature": sig})
    mpath = os.path.join(qdir, "manifest.json")
    fd = os.open(mpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)
    return qdir


def clam_findings(hits):
    return [checks.finding("clamav_hit", "antivirus", "CRITICAL", "high", sig, [path]) for path, sig in hits]


# ---------------------------------------------------------------- Zero Breach Toolkit (third party, Apache-2.0)

ZBT_URL = "https://github.com/interplains/Zero-Breach-Toolkit"
ZBT_COMMIT = "c41060571f6cb672e530045495a958fdd443ff5a"  # v0.1.8; first download is pinned and verified

# Third-party code and its data live inside THEK, in vendor/ (ignored by git, downloaded on first use)
HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
ZBT_CACHE = os.path.join(VENDOR, "zbt-indicators")


def zbt_dir():
    return os.path.join(VENDOR, "zero-breach-toolkit")


def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def zbt_script():
    p = os.path.join(zbt_dir(), "scan", "zero-breach-toolkit.py")
    return p if os.path.isfile(p) else None


def _git_head(path, ref="HEAD"):
    code, out = checks.run(["git", "-C", path, "rev-parse", "--verify", "-q", ref], timeout=30)
    return out.strip() if code == 0 else None


def zbt_install():
    """Download ZBT into vendor/ pinned to ZBT_COMMIT, and check that is exactly what we got."""
    if not shutil.which("git"):
        print(t("zbt.no_git"))
        return False
    dest = zbt_dir()
    print(t("zbt.about", url=ZBT_URL))
    _private_dir(VENDOR)
    if do(["git", "clone", "--quiet", ZBT_URL, dest]) is None:
        return False
    checks.run(["git", "-C", dest, "checkout", "-q", ZBT_COMMIT], timeout=60)
    if _git_head(dest) != ZBT_COMMIT:
        shutil.rmtree(dest, ignore_errors=True)
        print(t("zbt.bad_commit", commit=ZBT_COMMIT))
        return False
    return zbt_script() is not None


EXTERNAL = [{"name": "Zero Breach Toolkit", "dir": lambda: zbt_dir(), "url": ZBT_URL, "commit": ZBT_COMMIT,
             "license": "Apache-2.0", "install": lambda: zbt_install()}]


def update_external():
    """For each external component: fetch, show what changed upstream, and move only if the user says yes."""
    for ext in EXTERNAL:
        path = ext["dir"]()
        print("\n" + ext["name"] + " (" + ext["license"] + ", " + ext["url"] + ")")
        if not os.path.isdir(os.path.join(path, ".git")):
            ext["install"]()
            continue
        if do(["git", "-C", path, "fetch", "--quiet", "origin"]) is None:
            continue
        current = _git_head(path)
        latest = _git_head(path, "origin/HEAD") or _git_head(path, "origin/main")
        if latest is None:
            print(t("ext.no_remote"))
            continue
        if current == latest:
            print(t("ext.up_to_date", commit=current[:7]))
            continue
        _, log = checks.run(["git", "-C", path, "log", "--oneline", "--no-decorate", "HEAD.." + latest], timeout=60)
        commits = [l for l in log.splitlines() if l.strip()]
        _, stat_out = checks.run(["git", "-C", path, "diff", "--stat", "HEAD", latest], timeout=60)
        print(t("ext.changes", n=len(commits), current=(current or "?")[:7], latest=latest[:7]))
        for line in commits[:30]:
            print("    " + line)
        if len(commits) > 30:
            print("    " + t("ext.more", n=len(commits) - 30))
        print("    " + (stat_out.strip().splitlines() or [""])[-1])
        if do(["git", "-C", path, "checkout", "-q", latest]) is not None:
            print(t("ext.now", commit=(_git_head(path) or "?")[:7], pinned=ext["commit"][:7]))
    if zbt_script():
        zbt_update()


def zbt_iocs():
    """ZBT's own indicator set: its curated files plus its verified download cache. Local files only, no network.
    Returns (iocset, number of downloaded sources) or (None, 0) when ZBT is not usable."""
    scan = os.path.join(zbt_dir(), "scan")
    if not os.path.isdir(os.path.join(scan, "zbtriage")):
        return None, 0
    if scan not in sys.path:
        sys.path.insert(0, scan)
    try:
        from zbtriage import feeds
        from zbtriage.cli import _default_ioc_paths
        from zbtriage.iocs import load_any, merge
        cached = feeds.cached_sets(ZBT_CACHE)[0]
        return merge([load_any(p, allow_empty=True) for p in _default_ioc_paths()] + cached), len(cached)
    except Exception:  # noqa: BLE001 - any failure means "not available", reported by the caller
        return None, 0


def scan_journal(iocs, lines, block_chars=1_000_000):
    """Match a stream of log lines against the indicators, ~1 MB at a time. Nothing is written anywhere:
    only the matching lines (5 per indicator) are kept. Returns ({value: info}, number of lines)."""
    hits, n, buf, size = {}, 0, [], 0

    def flush(block):
        for ind in iocs.search("".join(block).lower()):
            h = hits.setdefault(ind.value, {"type": ind.type, "tier": ind.tier, "family": ind.family,
                                            "source": ind.source, "count": 0, "lines": []})
            for line in block:
                low = line.lower()
                if ind.value in low and any(i.value == ind.value for i in iocs.search(low)):
                    h["count"] += 1
                    if len(h["lines"]) < 5:
                        h["lines"].append(line.rstrip("\n")[:300])

    for line in lines:
        buf.append(line)
        size += len(line)
        n += 1
        if size >= block_chars:
            flush(buf)
            buf, size = [], 0
    if buf:
        flush(buf)
    return hits, n


def zbt_update():
    """Refresh ZBT's published indicator lists (its only network step)."""
    _private_dir(ZBT_CACHE)
    return do([sys.executable, "-X", "utf8", zbt_script(), "--no-menu", "--update", "--indicator-cache", ZBT_CACHE])


ZBT_STATUS = {0: ("OK", "info"), 2: ("CRITICAL", "high"), 3: ("WARN", "medium")}


def zbt_run(extra_args, report_dir):
    """Run ZBT with live output. Returns its exit code (None if it could not start)."""
    argv = [sys.executable, "-X", "utf8", zbt_script(), "--no-menu",
            "--json", os.path.join(report_dir, "zbt.json"),
            "--report", os.path.join(report_dir, "zbt.txt"),
            "--indicator-cache", _private_dir(ZBT_CACHE)] + list(extra_args)
    code, _ = checks.run(argv, timeout=None, capture=False)
    return code


def zbt_finding(code):
    status, sev = ZBT_STATUS.get(code, ("ERROR", "low"))
    return checks.finding("zbt", "spyware", status, sev, t("zbt.code", code=code), ["zbt.txt", "zbt.json"])
