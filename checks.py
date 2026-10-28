"""Read-only checks.

Nothing in this module changes the system or opens a network connection.
Everything that mutates lives in actions.py.
"""
import functools
import ipaddress
import os
import re
import shutil
import stat
import subprocess
import time

from i18n import t

TOOLS = ["clamscan", "freshclam", "rkhunter", "chkrootkit", "lynis", "debsums",
         "ufw", "firewall-cmd", "nft", "flatpak", "fwupdmgr", "smartctl",
         "pkexec", "sudo", "git", "gio", "nobara-sync"]


# ---------------------------------------------------------------- platform

def parse_os_release(text):
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def family_of(osr):
    os_id = osr.get("ID", "").lower()
    ids = [os_id] + osr.get("ID_LIKE", "").lower().split()
    if any(i in ("debian", "ubuntu") for i in ids):
        return "debian"
    if any(i in ("fedora", "rhel", "centos") for i in ids) or os_id in ("nobara", "rocky", "almalinux"):
        return "fedora"
    if any(i in ("arch", "manjaro", "endeavouros") for i in ids):
        return "arch"
    if "suse" in ids or os_id.startswith("opensuse") or os_id.startswith("sles"):
        return "suse"
    return "unknown"


@functools.lru_cache(maxsize=None)
def platform():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            osr = parse_os_release(f.read())
    except OSError:
        osr = {}
    return {"family": family_of(osr), "id": osr.get("ID", "unknown"),
            "version": osr.get("VERSION_ID", ""), "kernel": os.uname().release}


# ---------------------------------------------------------------- running

def elevate_prefix():
    """[] when already root, ["pkexec"] in a desktop session, ["sudo"] otherwise, None if impossible."""
    if os.geteuid() == 0:
        return []
    gui = os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")
    if gui and not os.environ.get("SSH_CONNECTION") and shutil.which("pkexec"):
        return ["pkexec"]
    if shutil.which("sudo"):
        return ["sudo"]
    return None


def run(argv, root=False, timeout=600, capture=True):
    """Run argv (a list, never a shell string). Returns (code or None, output)."""
    if shutil.which(argv[0]) is None:
        return None, "missing: " + argv[0]
    if root:
        prefix = elevate_prefix()
        if prefix is None:
            return None, "no pkexec/sudo available"
        argv = prefix + list(argv)
    # C locale so parsers see the same output on every system
    env = dict(os.environ, LC_ALL="C") if capture else None
    try:
        p = subprocess.run(argv, text=True, errors="replace", timeout=timeout, env=env,
                           stdin=subprocess.DEVNULL if capture else None,
                           stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.STDOUT if capture else None)
    except subprocess.TimeoutExpired:
        return None, "timeout after %ss" % timeout
    except OSError as e:
        return None, str(e)
    return p.returncode, p.stdout or ""


def tools():
    return {name: shutil.which(name) for name in TOOLS}


def data_dir(*parts):
    """$XDG_DATA_HOME/thek[/parts], created 0700."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    path = os.path.join(base, "thek", *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    d = os.path.join(base, "thek")
    for p in [d] + [os.path.join(d, *parts[:i + 1]) for i in range(len(parts))]:
        os.chmod(p, 0o700)
    return path


# ---------------------------------------------------------------- per family

def _dnf():
    return "dnf5" if shutil.which("dnf5") else "dnf"


def family_cmds(family):
    """Package-manager commands per family. None = not supported there."""
    if family == "debian":
        return {"install": ["apt-get", "install", "-y"],
                "clean": [["apt-get", "clean"]],
                "autoremove_preview": ["apt-get", "autoremove", "--dry-run"],
                "autoremove": ["apt-get", "autoremove", "-y"],
                "updates_cached": ["apt", "list", "--upgradable"],
                "upgrade": [["apt-get", "update"], ["apt-get", "full-upgrade"]],
                "integrity": ["debsums", "-s"],
                "owner_of": ["dpkg", "-S"]}
    if family == "fedora":
        dnf = _dnf()
        upgrade = [["nobara-sync", "cli"]] if shutil.which("nobara-sync") else [[dnf, "upgrade", "--refresh"]]
        return {"install": [dnf, "install", "-y"],
                "clean": [[dnf, "clean", "all"]],
                "autoremove_preview": [dnf, "autoremove", "--assumeno"],
                "autoremove": [dnf, "autoremove", "-y"],
                "updates_cached": [dnf, "check-update", "--cacheonly", "-q"],
                "upgrade": upgrade,
                "integrity": ["rpm", "-Va"],
                "owner_of": ["rpm", "-qf"]}
    if family == "arch":
        # autoremove gets the orphan list (pacman -Qdtq) appended by actions.py
        return {"install": ["pacman", "-S", "--needed", "--noconfirm"],
                "clean": [["pacman", "-Sc", "--noconfirm"]],
                "autoremove_preview": ["pacman", "-Qdtq"],
                "autoremove": ["pacman", "-Rns", "--noconfirm"],
                "updates_cached": ["pacman", "-Qu"],
                "upgrade": [["pacman", "-Syu"]],
                "integrity": ["pacman", "-Qkk"],
                "owner_of": ["pacman", "-Qo"]}
    if family == "suse":
        return {"install": ["zypper", "--non-interactive", "install"],
                "clean": [["zypper", "clean", "--all"]],
                "autoremove_preview": None,
                "autoremove": None,
                "updates_cached": ["zypper", "--no-refresh", "list-updates"],
                "upgrade": [["zypper", "refresh"], ["zypper", "update"]],
                "integrity": ["rpm", "-Va"],
                "owner_of": ["rpm", "-qf"]}
    return {}


# tool (binary) -> family -> package name. None = not in the official repos.
PACKAGES = {
    "clamscan":   {"debian": "clamav", "fedora": "clamav", "arch": "clamav", "suse": "clamav"},
    "freshclam":  {"debian": "clamav-freshclam", "fedora": "clamav-freshclam", "arch": "clamav", "suse": "clamav"},
    "rkhunter":   {"debian": "rkhunter", "fedora": "rkhunter", "arch": "rkhunter", "suse": None},
    "chkrootkit": {"debian": "chkrootkit", "fedora": "chkrootkit", "arch": None, "suse": None},
    "lynis":      {"debian": "lynis", "fedora": "lynis", "arch": "lynis", "suse": "lynis"},
    "debsums":    {"debian": "debsums"},
    "ufw":        {"debian": "ufw"},
    "firewall-cmd": {"fedora": "firewalld", "arch": "firewalld", "suse": "firewalld"},
    "unattended-upgrade": {"debian": "unattended-upgrades"},
    "dnf-automatic": {"fedora": "dnf-automatic"},
    "git":        {"debian": "git", "fedora": "git", "arch": "git", "suse": "git"},  # downloads Zero Breach Toolkit
}
WANTED = ["clamscan", "freshclam", "rkhunter", "chkrootkit", "lynis", "debsums", "git"]
MISSING_HINT = {"arch": "AUR", "fedora": "EPEL (RHEL/Rocky/Alma)", "suse": "software.opensuse.org (OBS)"}
# RHEL rebuilds keep the security tools in EPEL, which THEK suggests but never enables
EPEL_IDS = ("rhel", "rocky", "almalinux", "centos", "ol")


# ---------------------------------------------------------------- findings

def finding(fid, area, status, severity="info", detail="", evidence=None, action=None, title=None):
    suggestion = t("s." + fid)
    return {"id": fid, "area": area, "title": title or t("c." + fid), "status": status,
            "severity": severity, "detail": detail, "evidence": list(evidence or [])[:20],
            "suggestion": "" if suggestion == "s." + fid else suggestion, "action": action}


def check(fid, area):
    """Decorator: an exception inside a check becomes an ERROR finding, never aborts the audit."""
    def wrap(fn):
        @functools.wraps(fn)
        def inner():
            try:
                return fn()
            except Exception as e:  # noqa: BLE001 - report, don't crash
                return [finding(fid, area, "ERROR", "low", detail="%s: %s" % (type(e).__name__, e))]
        inner.fid = fid
        return inner
    return wrap


def _natkey(s):
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"(\d+)", s)]


# ---------------------------------------------------------------- secrets

# (?<!…) keeps "disk-utility…" or "task-unfinished…" from matching as sk-…
_B = r"(?<![A-Za-z0-9])"
SECRET_PATTERNS = [
    ("huggingface", re.compile(_B + r"hf_[A-Za-z0-9]{30,}"), "hf_"),
    ("github", re.compile(_B + r"github_pat_[A-Za-z0-9_]{40,}"), "github_pat_"),
    ("github", re.compile(_B + r"gh[pousr]_[A-Za-z0-9]{30,}"), None),
    ("anthropic", re.compile(_B + r"sk-ant-[A-Za-z0-9_-]{20,}"), "sk-ant-"),
    ("openai", re.compile(_B + r"sk-[A-Za-z0-9_-]{20,}"), "sk-"),
    ("aws", re.compile(_B + r"AKIA[0-9A-Z]{16}"), "AKIA"),
    ("slack", re.compile(_B + r"xox[baprs]-[A-Za-z0-9-]{10,}"), None),
]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def censor_secret(token, prefix=None):
    """Known prefix + 4 characters + '…'. Never the whole value."""
    if prefix is None:
        m = re.match(r"[A-Za-z]+[_-]", token)
        prefix = m.group(0) if m else ""
    return token[:len(prefix) + 4] + "…"


def find_secrets(text):
    """[(kind, censored)] for every token in text. The full value never leaves this function."""
    out, seen = [], set()
    for kind, rx, prefix in SECRET_PATTERNS:
        for m in rx.finditer(text):
            if any(m.start() >= a and m.end() <= b for a, b in seen):
                continue  # sk-ant-… already matched; don't report it again as sk-…
            seen.add((m.start(), m.end()))
            out.append((kind, censor_secret(m.group(0), prefix)))
    return out


def censor_all(text):
    for _, rx, prefix in SECRET_PATTERNS:
        text = rx.sub(lambda m, p=prefix: censor_secret(m.group(0), p), text)
    return text


def scan_roots():
    roots = [os.path.expanduser("~")]
    roots += [r for r in os.environ.get("THEK_SCAN_ROOTS", "").split(":") if r and os.path.isdir(r)]
    return roots


SKIP_DIRS = {".git", "node_modules", ".cache"}


def walk_files(roots):
    skip = os.path.realpath(data_dir())
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                           and os.path.realpath(os.path.join(dirpath, d)) != skip]
            for name in filenames:
                yield dirpath, name


# ---------------------------------------------------------------- quick checks

@check("reboot_pending", "system")
def reboot_pending():
    running = os.uname().release
    try:
        installed = sorted(os.listdir("/lib/modules"), key=_natkey)
    except OSError:
        installed = []
    if os.path.exists("/var/run/reboot-required"):
        return [finding("reboot_pending", "system", "WARN", "low", "/var/run/reboot-required")]
    if not installed:
        return [finding("reboot_pending", "system", "UNAVAILABLE", "low", "/lib/modules")]
    if running not in installed or installed[-1] != running:
        return [finding("reboot_pending", "system", "WARN", "low",
                        t("d.reboot", running=running, newest=installed[-1]))]
    return [finding("reboot_pending", "system", "OK", detail=running)]


def count_updates(family, code, out):
    """Number of pending updates from the cached package lists, or None if unknown."""
    lines = [l for l in out.splitlines() if l.strip()]
    if family == "debian":
        return sum(1 for l in lines if "upgradable from" in l)
    if family == "fedora":
        if code not in (0, 100):
            return None
        return sum(1 for l in lines if len(l.split()) >= 3 and "." in l.split()[0])
    if family == "arch":
        return sum(1 for l in lines if "->" in l) if code in (0, 1) else None
    if family == "suse":
        return sum(1 for l in lines if l.startswith("v ")) if code in (0, 100, 101) else None
    return None


@check("updates", "packages")
def updates():
    fam = platform()["family"]
    cmd = family_cmds(fam).get("updates_cached")
    if not cmd:
        return [finding("updates", "packages", "UNAVAILABLE", "medium", t("d.unsupported"))]
    code, out = run(cmd, timeout=120)
    n = count_updates(fam, code, out) if code is not None else None
    if n is None:
        return [finding("updates", "packages", "UNAVAILABLE", "medium", out.strip()[-300:])]
    if n:
        return [finding("updates", "packages", "WARN", "medium", t("d.updates", n=n), action="upgrade")]
    return [finding("updates", "packages", "OK", detail=t("d.updates", n=0))]


def _active(unit):
    code, out = run(["systemctl", "is-active", unit], timeout=20)
    return code is not None and out.strip() == "active"


@check("firewall", "network")
def firewall():
    if not shutil.which("systemctl"):
        return [finding("firewall", "network", "UNAVAILABLE", "high", "systemctl")]
    for unit in ("firewalld", "ufw"):
        if _active(unit):
            return [finding("firewall", "network", "OK", detail=unit)]
    return [finding("firewall", "network", "UNAVAILABLE", "high", t("d.firewall_needs_full"), action="firewall")]


@check("mac", "system")
def mac():
    parts, ok = [], False
    if shutil.which("getenforce"):
        _, out = run(["getenforce"], timeout=10)
        parts.append("SELinux: " + out.strip())
        ok = ok or out.strip() == "Enforcing"
    try:
        with open("/sys/module/apparmor/parameters/enabled") as f:
            aa = f.read().strip()
        parts.append("AppArmor: " + aa)
        ok = ok or aa == "Y"
    except OSError:
        pass
    if not parts:
        return [finding("mac", "system", "UNAVAILABLE", "low")]
    return [finding("mac", "system", "OK" if ok else "WARN", "low", ", ".join(parts))]


def parse_ss(text):
    """[(proto, local_address, process)] from `ss -tulnpH`."""
    out = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        out.append((cols[0], cols[4], proc.group(1) if proc else ""))
    return out


def is_loopback(addr):
    host = addr.rsplit(":", 1)[0].strip("[]")
    if "%lo" in host:
        return True
    host = host.split("%")[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@check("listening_ports", "network")
def listening_ports():
    code, out = run(["ss", "-tulnpH"], timeout=20)
    if code is None:
        return [finding("listening_ports", "network", "UNAVAILABLE", "medium", out)]
    exposed = ["%s %s %s" % (p, a, proc) for p, a, proc in parse_ss(out) if not is_loopback(a)]
    if exposed:
        return [finding("listening_ports", "network", "WARN", "medium", t("d.ports", n=len(exposed)), exposed)]
    return [finding("listening_ports", "network", "OK")]


@check("ssh_user_perms", "ssh")
def ssh_user_perms():
    d = os.path.expanduser("~/.ssh")
    if not os.path.isdir(d):
        return [finding("ssh_user_perms", "ssh", "OK", detail="~/.ssh")]
    bad = []
    if os.stat(d).st_mode & 0o077:
        bad.append("~/.ssh %o" % stat.S_IMODE(os.stat(d).st_mode))
    for name in os.listdir(d):
        p = os.path.join(d, name)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        try:
            with open(p, errors="replace") as f:
                head = f.read(100)
        except OSError:
            continue
        if PRIVATE_KEY.search(head) and os.stat(p).st_mode & 0o077:
            bad.append("~/.ssh/%s %o" % (name, stat.S_IMODE(os.stat(p).st_mode)))
    res = [finding("ssh_user_perms", "ssh", "WARN" if bad else "OK", "high" if bad else "info", evidence=bad)]
    ak = os.path.join(d, "authorized_keys")
    if os.path.isfile(ak):
        with open(ak, errors="replace") as f:
            ev = [e for e in (parse_authorized_key(l) for l in f) if e]
        res.append(finding("authorized_keys", "ssh", "OK", "info", t("d.keys", n=len(ev)), ev))
    return res


_KEYLINE = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[\w@.-]+)\s+\S+\s*(.*)$")


def parse_authorized_key(line):
    """'type [options] key-comment: comment', or None for blanks/comments. The key itself is never kept."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _KEYLINE.search(line)
    if not m:
        return "? key-comment: -"
    opts = " +options" if line[:m.start(1)].strip() else ""
    return "%s%s key-comment: %s" % (m.group(1), opts, m.group(2).strip() or "-")


@check("autostart", "persistence")
def autostart():
    ev = []
    d = os.path.expanduser("~/.config/autostart")
    if os.path.isdir(d):
        ev += ["autostart: " + n for n in sorted(os.listdir(d)) if n.endswith(".desktop")]
    code, out = run(["systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend"], timeout=20)
    if code == 0:
        ev += ["systemd --user: " + l.split()[0] for l in out.splitlines() if l.strip()]
    code, out = run(["crontab", "-l"], timeout=20)
    if code == 0:
        ev += ["crontab: " + l for l in out.splitlines() if l.strip() and not l.startswith("#")]
    return [finding("autostart", "persistence", "OK", "info", t("d.autostart", n=len(ev)), ev)]


@check("odd_processes", "processes")
def odd_processes():
    deleted, tmp, hidden = [], [], 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % pid)
            with open("/proc/%s/comm" % pid) as f:
                comm = f.read().strip()
        except OSError:
            hidden += 1
            continue
        if exe.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
            tmp.append("%s %s %s" % (pid, comm, exe))
        elif exe.endswith(" (deleted)"):
            deleted.append("%s %s %s" % (pid, comm, exe))
    res = []
    if tmp:
        res.append(finding("odd_processes_tmp", "processes", "CRITICAL", "high", evidence=tmp))
    if deleted:
        res.append(finding("odd_processes", "processes", "WARN", "medium", evidence=deleted))
    if not res:
        res.append(finding("odd_processes", "processes", "OK", detail=t("d.hidden_procs", n=hidden)))
    return res


def clamav_db_age_days(version_line, now=None):
    """`ClamAV 1.4.6/28080/Sun Aug  2 02:24:19 2026` -> age in days, or None."""
    parts = version_line.strip().split("/")
    if len(parts) < 3:
        return None
    stamp = time.mktime(time.strptime(" ".join(parts[2].split()), "%a %b %d %H:%M:%S %Y"))
    return int(((now or time.time()) - stamp) // 86400)


FRESHCLAM_UNITS = ["clamav-freshclam.service", "clamav-freshclam-once.timer", "freshclam.service", "freshclam.timer"]


@check("clamav_signatures", "antivirus")
def clamav_signatures():
    if not shutil.which("clamscan"):
        return [finding("clamav_signatures", "antivirus", "UNAVAILABLE", "medium", action="install")]
    _, out = run(["clamscan", "--version"], timeout=30)
    age = clamav_db_age_days(out)
    res = []
    if age is None:
        res.append(finding("clamav_signatures", "antivirus", "WARN", "medium", out.strip(), action="freshclam"))
    elif age > 7:
        res.append(finding("clamav_signatures", "antivirus", "WARN", "medium", t("d.clam_age", n=age), action="freshclam"))
    else:
        res.append(finding("clamav_signatures", "antivirus", "OK", detail=t("d.clam_age", n=age)))
    if shutil.which("systemctl") and not any(_active(u) for u in FRESHCLAM_UNITS):
        res.append(finding("freshclam_service", "antivirus", "WARN", "low", action="freshclam_auto"))
    return res


@check("secret_names", "secrets")
def secret_names():
    hits = []
    for dirpath, name in walk_files(scan_roots()):
        for kind, censored in find_secrets(name):
            hits.append("%s: %s" % (kind, os.path.join(dirpath, censor_all(name))))
    if hits:
        return [finding("secret_names", "secrets", "CRITICAL", "high", t("d.secrets", n=len(hits)), hits)]
    return [finding("secret_names", "secrets", "OK")]


@check("secret_contents", "secrets")
def secret_contents():
    """Tokens and private keys inside text files under 1 MB. Slow: only from menu option 5."""
    import sys
    ssh_dir = os.path.expanduser("~/.ssh") + os.sep
    hits, n = [], 0
    for dirpath, name in walk_files(scan_roots()):
        p = os.path.join(dirpath, name)
        n += 1
        if n % 2000 == 0:
            sys.stderr.write("\r  %d…" % n)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size < 1024 * 1024:
                continue
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        shown = censor_all(p)
        for kind, censored in find_secrets(text):
            hits.append("%s: %s → %s" % (kind, shown, censored))
        if PRIVATE_KEY.search(text) and not (p.startswith(ssh_dir) and not st.st_mode & 0o077):
            hits.append("private-key: " + shown)
    sys.stderr.write("\r")
    if hits:
        return [finding("secret_contents", "secrets", "CRITICAL", "high", t("d.secrets_in", n=len(hits), files=n), hits)]
    return [finding("secret_contents", "secrets", "OK", detail=t("d.secrets_in", n=0, files=n))]


@check("world_writable_home", "files")
def world_writable_home():
    found = []
    for dirpath, name in walk_files([os.path.expanduser("~")]):
        p = os.path.join(dirpath, name)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002:
            found.append(p)
            if len(found) >= 50:
                break
    if found:
        return [finding("world_writable_home", "files", "WARN", "medium", t("d.files", n=len(found)), found)]
    return [finding("world_writable_home", "files", "OK")]


@check("flatpak_broad_perms", "apps")
def flatpak_broad_perms():
    if not shutil.which("flatpak"):
        return []
    code, out = run(["flatpak", "list", "--app", "--columns=application"], timeout=60)
    if code != 0:
        return [finding("flatpak_broad_perms", "apps", "UNAVAILABLE", "low", out.strip()[-200:])]
    broad = []
    for app in [l.strip() for l in out.splitlines() if l.strip()]:
        _, meta = run(["flatpak", "info", "-M", app], timeout=30)
        m = re.search(r"^filesystems=(.*)$", meta, re.M)
        if m and any(fs.split(":")[0] in ("host", "host-os", "host-etc", "home") for fs in m.group(1).split(";")):
            broad.append("%s: %s" % (app, m.group(1)))
    return [finding("flatpak_broad_perms", "apps", "OK", "info", t("d.flatpak", n=len(broad)), broad)]


def count_failed_logins(text):
    """{ip: count} from sshd journal lines."""
    counts = {}
    for line in text.splitlines():
        if re.search(r"Failed password|Invalid user|authentication failure", line):
            m = re.search(r"from (\S+)", line) or re.search(r"rhost=(\S+)", line)
            ip = m.group(1) if m else "?"
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def _is_lan(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@check("failed_logins", "ssh")
def failed_logins():
    if not shutil.which("journalctl"):
        return [finding("failed_logins", "ssh", "UNAVAILABLE", "medium", "journalctl")]
    code, out = run(["journalctl", "-u", "sshd", "-u", "ssh", "--since", "-7d", "--no-pager", "-q", "-o", "cat"], timeout=60)
    if code is None or "insufficient permissions" in out or "not seeing messages" in out:
        return [finding("failed_logins", "ssh", "UNAVAILABLE", "medium", out.strip()[-200:])]
    counts = count_failed_logins(out)
    ev = ["%s: %d" % (ip, n) for ip, n in sorted(counts.items(), key=lambda x: -x[1])]
    if any(n > 10 and not _is_lan(ip) for ip, n in counts.items()):
        return [finding("failed_logins", "ssh", "WARN", "medium", t("d.logins", n=sum(counts.values())), ev)]
    return [finding("failed_logins", "ssh", "OK", detail=t("d.logins", n=sum(counts.values())), evidence=ev)]


QUICK = [reboot_pending, updates, firewall, mac, listening_ports, ssh_user_perms, autostart,
         odd_processes, clamav_signatures, secret_names, world_writable_home,
         flatpak_broad_perms, failed_logins]


def run_checks(funcs):
    out = []
    for f in funcs:
        out += f()
    return out


# ---------------------------------------------------------------- full audit (root once)

def have(binary):
    """which() that also looks in sbin, which is often not in a normal user's PATH."""
    path = os.environ.get("PATH", "") + ":/usr/local/sbin:/usr/sbin:/sbin"
    return shutil.which(binary, path=path) is not None


INTEGRITY_PROBE = {"fedora": "rpm -Va 2>/dev/null", "suse": "rpm -Va 2>/dev/null",
                   "debian": "debsums -s 2>&1", "arch": "pacman -Qkk 2>&1"}
INTEGRITY_TOOL = {"fedora": "rpm", "suse": "rpm", "debian": "debsums", "arch": "pacman"}

# (name, binary that must exist or None, shell command). Only literals: nothing typed by the user goes in here.
ROOT_PROBES = [
    ("rkhunter", "rkhunter", "rkhunter --check --sk --rwo --nocolors"),
    ("chkrootkit", "chkrootkit", "chkrootkit -q"),
    ("lynis", "lynis", "lynis audit system --quick --no-colors >/dev/null 2>&1; cat /var/log/lynis-report.dat"),
    ("integrity", "@integrity", "@integrity"),
    ("suid", None, "find / -xdev -perm -4000 -type f 2>/dev/null"),
    ("sshd", "sshd", "sshd -T"),
    ("shadow_empty", None, "awk -F: '($2==\"\"){print $1}' /etc/shadow"),
    ("cron_system", None, "ls -la /etc/cron.* /var/spool/cron"),
    ("smart", "smartctl", "for d in $(lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'); "
                          "do echo \"== $d\"; smartctl -H /dev/$d; done"),
    ("nft", "nft", "nft list ruleset"),
    ("apparmor", "aa-status", "aa-status --enabled; echo $?"),
    ("ufw", "ufw", "ufw status verbose"),
]
# Absent system components are not gaps (no sshd = no SSH server); absent security tools are.
SKIP_IF_ABSENT = {"sshd", "nft", "apparmor", "ufw"}
INSTALLABLE = {"rkhunter", "chkrootkit", "lynis", "integrity"}


def build_root_script(family):
    """(script, unavailable_findings). The script runs every available probe between markers."""
    parts, missing = [], []
    for name, binary, cmd in ROOT_PROBES:
        if cmd == "@integrity":
            cmd, binary = INTEGRITY_PROBE.get(family), INTEGRITY_TOOL.get(family)
            if not cmd:
                missing.append(finding("integrity", "integrity", "UNAVAILABLE", "medium", t("d.unsupported")))
                continue
        if binary and not have(binary):
            if name in SKIP_IF_ABSENT:
                continue
            missing.append(finding(name, _AREA.get(name, "system"), "UNAVAILABLE", "medium", t("d.missing_tool", tool=binary),
                                   action="install" if name in INSTALLABLE else None))
            continue
        parts.append("echo '### THEK:%s'\n( %s ) 2>&1\necho \"### END:%s:$?\"" % (name, cmd, name))
    return "\n".join(parts), missing


def split_probes(output):
    """{name: (exit_code or None, text)} from the marked output of the root script."""
    out, name, buf = {}, None, []
    for line in output.splitlines():
        m = re.match(r"^### THEK:(\w+)$", line)
        e = re.match(r"^### END:(\w+):(\d+)$", line)
        if m:
            name, buf = m.group(1), []
        elif e and name == e.group(1):
            out[name] = (int(e.group(2)), "\n".join(buf))
            name = None
        elif name:
            buf.append(line)
    if name:  # cut off (timeout / killed)
        out[name] = (None, "\n".join(buf))
    return out


_AREA = {"rkhunter": "rootkits", "chkrootkit": "rootkits", "lynis": "hardening", "integrity": "integrity",
         "suid": "integrity", "sshd": "ssh", "shadow_empty": "accounts", "cron_system": "persistence",
         "smart": "disks", "nft": "network", "apparmor": "system", "ufw": "network"}

_SYSDIRS = ("/usr/bin/", "/usr/sbin/", "/usr/lib", "/bin/", "/sbin/", "/lib")


def parse_rkhunter(text):
    return [l.strip() for l in text.splitlines() if "Warning:" in l]


def parse_chkrootkit(text):
    return [l.rstrip() for l in text.splitlines() if l.strip()]


def parse_lynis(text):
    """(hardening_index or None, [warnings]) from /var/log/lynis-report.dat."""
    index, warnings = None, []
    for line in text.splitlines():
        if line.startswith("hardening_index="):
            index = line.split("=", 1)[1].strip()
        elif line.startswith("warning[]="):
            warnings.append(line.split("=", 1)[1].strip())
    return index, warnings


def parse_integrity(family, text):
    """Changed files in system binary/library dirs. Config files and timestamp-only changes are noise."""
    out = []
    for line in text.splitlines():
        if family in ("fedora", "suse"):
            m = re.match(r"^([.\w?]{9})\s+(?:([cdglr])\s+)?(/\S.*)$", line)
            if m and "5" in m.group(1) and m.group(2) != "c" and m.group(3).startswith(_SYSDIRS):
                out.append(line.strip())
        elif family == "debian":
            m = re.search(r"(/\S+)", line)
            if m and m.group(1).startswith(_SYSDIRS):
                out.append(line.strip())
        elif family == "arch":
            m = re.search(r"(/\S+) \((?:SHA256|.*checksum)", line)
            if m and m.group(1).startswith(_SYSDIRS):
                out.append(line.strip())
    return out


def unowned(paths, family):
    """Paths no installed package claims."""
    cmd = family_cmds(family).get("owner_of")
    if not cmd or not paths:
        return []
    _, out = run(cmd + paths, timeout=300)
    bad = []
    for p in paths:
        for line in out.splitlines():
            if p in line and re.search(r"not owned|no path found|No package owns", line):
                bad.append(p)
                break
    return bad


def parse_sshd(text):
    risky = []
    for line in text.splitlines():
        k, _, v = line.strip().partition(" ")
        if k in ("passwordauthentication", "permitrootlogin", "permitemptypasswords") and v == "yes":
            risky.append(line.strip())
    return risky


def parse_smart(text):
    """[(disk, 'OK'|'FAILED'|'UNKNOWN', last line)]."""
    out = []
    for block in re.split(r"^== ", text, flags=re.M)[1:]:
        disk, _, body = block.partition("\n")
        if re.search(r"FAILED", body):
            state = "FAILED"
        elif re.search(r"PASSED|SMART Health Status: OK", body):
            state = "OK"
        else:
            state = "UNKNOWN"  # zram, USB bridges, virtual disks: no SMART to read
        last = [l for l in body.splitlines() if l.strip()]
        out.append((disk.strip(), state, last[-1].strip() if last else ""))
    return out


def nft_has_rules(text):
    return any(re.match(r"^\s+(ip6?|tcp|udp|ct|iif|oif|iifname|oifname|meta|counter|drop|accept|reject|jump|goto)\b", l)
               for l in text.splitlines())


def parse_probes(probes, family):
    """Findings from split_probes() output."""
    res = []

    def add(fid, *a, **kw):
        res.append(finding(fid, _AREA.get(fid.split(".")[0], "system"), *a, **kw))

    if "rkhunter" in probes:
        w = parse_rkhunter(probes["rkhunter"][1])
        add("rkhunter", "WARN" if w else "OK", "high" if w else "info", t("d.n", n=len(w)), w)
    if "chkrootkit" in probes:
        w = parse_chkrootkit(probes["chkrootkit"][1])
        add("chkrootkit", "WARN" if w else "OK", "high" if w else "info", t("d.n", n=len(w)), w)
    if "lynis" in probes:
        index, w = parse_lynis(probes["lynis"][1])
        if index is None:
            add("lynis", "ERROR", "low", probes["lynis"][1][-300:])
        else:
            add("lynis", "WARN" if w else "OK", "medium" if w else "info", t("d.lynis", index=index, n=len(w)), w)
    if "integrity" in probes:
        w = parse_integrity(family, probes["integrity"][1])
        add("integrity", "WARN" if w else "OK", "high" if w else "info", t("d.n", n=len(w)), w)
    if "suid" in probes:
        paths = [l.strip() for l in probes["suid"][1].splitlines() if l.startswith("/")]
        bad = unowned(paths, family)
        add("suid", "CRITICAL" if bad else "OK", "high" if bad else "info", t("d.suid", n=len(paths), bad=len(bad)), bad)
    # these two print an error instead of data when they fail: never read an error as a result
    for name in ("sshd", "shadow_empty"):
        if name in probes and probes[name][0] != 0:
            add(name, "UNAVAILABLE", "medium", probes[name][1].strip()[-200:])
            del probes[name]
    if "sshd" in probes:
        w = parse_sshd(probes["sshd"][1])
        add("sshd", "WARN" if w else "OK", "medium" if w else "info", evidence=w)
    if "shadow_empty" in probes:
        users = [l.strip() for l in probes["shadow_empty"][1].splitlines() if l.strip()]
        add("shadow_empty", "CRITICAL" if users else "OK", "high" if users else "info", evidence=users)
    if "cron_system" in probes:
        lines = [l for l in probes["cron_system"][1].splitlines() if l.strip()]
        add("cron_system", "OK", "info", t("d.n", n=len(lines)), lines)
    if "smart" in probes:
        for disk, state, last in parse_smart(probes["smart"][1]):
            status = {"OK": "OK", "FAILED": "CRITICAL", "UNKNOWN": "UNAVAILABLE"}[state]
            res.append(finding("smart", "disks", status, "high" if state == "FAILED" else "info",
                               "%s: %s" % (disk, last), title=t("c.smart") + " /dev/" + disk))
    if "apparmor" in probes:
        on = probes["apparmor"][1].strip().endswith("0")
        add("apparmor", "OK" if on else "WARN", "low", "AppArmor " + ("on" if on else "off"))
    return res


def full_audit(quick):
    """Run every root probe with ONE elevation. Returns (findings, root_ran). Updates the quick firewall finding."""
    fam = platform()["family"]
    script, res = build_root_script(fam)
    print(t("d.full_wait"))
    code, out = run(["bash", "-c", script], root=True, timeout=7200)
    probes = split_probes(out)
    if not probes:
        reason = t("d.root_denied") + (" (%s)" % out.strip()[-200:] if out.strip() else "")
        for name, _, _ in ROOT_PROBES:
            if name not in [f["id"] for f in res] and name not in SKIP_IF_ABSENT:
                res.append(finding(name, _AREA.get(name, "system"), "UNAVAILABLE", "medium", reason))
        return res, False
    res += parse_probes(probes, fam)
    _firewall_verdict(quick, probes)
    return res, True


def _firewall_verdict(quick, probes):
    """firewalld or ufw active, or nftables with rules. None of them -> CRITICAL."""
    fw = next((f for f in quick if f["id"] == "firewall"), None)
    if fw is None:
        return
    ufw_active = "ufw" in probes and re.search(r"Status: active", probes["ufw"][1])
    nft_rules = "nft" in probes and nft_has_rules(probes["nft"][1])
    if fw["status"] == "OK" and fw["detail"] == "ufw" and "ufw" in probes and not ufw_active:
        fw.update(status="UNAVAILABLE")  # ufw.service can be "active" while ufw itself is disabled
    if fw["status"] == "OK":
        return
    if ufw_active:
        fw.update(status="OK", severity="info", detail="ufw", action=None)
    elif nft_rules:
        fw.update(status="OK", severity="info", detail="nftables", action=None)
    else:
        fw.update(status="CRITICAL", severity="high", detail=t("d.no_firewall"), action="firewall")
