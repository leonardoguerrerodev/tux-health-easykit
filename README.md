# Tux Health EasyKit (THEK)

**THEK = Tux Health EasyKit**: a first-aid kit for your Linux, made for people who are not security experts.

A terminal menu to **audit, scan, clean and harden a Linux machine**, with reports written so that
**any AI model** (local or cloud) can read them and tell you what to do.

It does not reinvent anything: it puts well-known tools (ClamAV, rkhunter, chkrootkit, Lynis,
[Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) and your package manager)
behind one menu, reads their output and turns it into one report.

[Leer en español](README.es.md)

> **A clean result means "nothing known was found in what could be checked". It does not mean
> your machine is safe.** Anything THEK could not check is reported as `UNAVAILABLE`, never
> as clean. If you believe you are being targeted, get expert help first:
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/).

## Quick start

```sh
git clone <this repository> tux-health-easykit
cd tux-health-easykit
python3 THEK_run.py
```

Only Python 3.9+ is needed: no `pip install`, no dependencies. **Option 1 · Total review does
everything in one pass**: it asks what it needs first (downloads, installing tools), then runs on its
own and leaves a single report.

```
python3 THEK_run.py                 # menu (option 1 = everything)
python3 THEK_run.py --audit quick   # no root, no network
python3 THEK_run.py --audit full    # asks for root once
python3 THEK_run.py --install       # install missing tools (asks first)
python3 THEK_run.py --doctor        # what THEK sees on this machine
python3 THEK_run.py --lang en       # or es; default follows your locale
```

`--audit` exit codes: `0` nothing found, `2` something critical, `3` warnings or gaps.

## What it does

| Menu | What |
|---|---|
| Total review | all of the below in one pass: full audit, journal against spyware indicators, optionally the Zero Breach Toolkit scan, one report, optional export |
| Quick audit | pending updates and reboot, firewall, SELinux/AppArmor, open ports, `~/.ssh` permissions, authorized keys, autostart programs, processes running from `/tmp` or with deleted executables, ClamAV signature age, tokens in file names, world-writable files, Flatpak permissions, failed SSH logins |
| Full audit | everything above plus, with **one** root prompt: rkhunter, chkrootkit, Lynis, package integrity (`rpm -Va` / `debsums` / `pacman -Qkk`), SUID programs no package owns, `sshd` settings, accounts without password, system cron, disk SMART health, nftables |
| ClamAV | update signatures; scan Downloads, home, a path or the whole system; move detections to a quarantine |
| Spyware | runs Zero Breach Toolkit (pinned to a reviewed commit), and can check your whole systemd journal against its indicators (streamed, no copy written to disk) |
| Secrets | finds tokens (GitHub, Hugging Face, OpenAI, Anthropic, AWS, Slack) and private keys inside files |
| Cleanup | package cache, unused packages (with preview), unused Flatpak runtimes, journal, trash, thumbnails, coredumps |
| Hardening | firewall, automatic ClamAV signature updates, automatic updates where the distro recommends them |
| Update | your distro's update tool, Flatpak, firmware |
| Update external components | shows what changed in Zero Breach Toolkit upstream and moves only if you say yes; refreshes its indicators |
| Export for your AI | writes the last report to `output_docs/` as a dated `.md` (redacted or full) for you to give to the AI you trust |

Every action that changes the system **shows the exact command and asks first**. Nothing detected
is ever deleted: it goes to the quarantine with a manifest. SSH server settings are only reported,
never edited (a wrong edit can lock you out).

## Supported distributions

| Family | Examples | Package manager |
|---|---|---|
| debian | Debian, Ubuntu, Kubuntu, Mint, Pop!_OS, Kali, Raspberry Pi OS | apt |
| fedora | Fedora, Nobara, RHEL, Rocky, AlmaLinux, CentOS Stream | dnf |
| arch | Arch, Manjaro, EndeavourOS | pacman |
| suse | openSUSE Leap / Tumbleweed, SLES | zypper |

Other distributions run the generic checks; package actions say "not supported".
chkrootkit is not in Arch's official repositories (AUR). On RHEL/Rocky/Alma the security tools come
from EPEL. THEK suggests those but never enables them for you.

## Privacy

- **No telemetry, no AI connection.** THEK itself never opens a network connection, and it never
  talks to any AI. The network is used only by the tools behind actions you start: updating,
  installing, downloading signatures or indicators.
- **Reports stay on your machine**, in `~/.local/share/thek/` (`$XDG_DATA_HOME`), folders `0700`
  and files `0600`. Only what you export goes to `output_docs/`, which git ignores.
- **Secrets are never stored whole**: only their type, where they are, and the first characters.
- **Two versions of each report**: `report.md` (full) and `report.redacted.md` (without your user
  name, host name, home path, IP and MAC addresses, emails and SSH key comments).
- **The journal check is streamed.** The system journal is read line by line and never copied;
  only matching lines (at most 5 per indicator) go into the report.

## What THEK downloads and where

THEK is self-contained: you clone one folder and everything it needs either lives inside it or
comes from your distribution.

| Piece | Where | Why |
|---|---|---|
| Zero Breach Toolkit (code) | `vendor/zero-breach-toolkit/`, downloaded on first use | Python that runs as your user; pinned to a reviewed commit and checked after download |
| Its indicator lists (~10 MB) | `vendor/zbt-indicators/` | third-party data that changes often |
| ClamAV, rkhunter, chkrootkit, Lynis | your system, via **Install missing tools** | they run as root: your distro's signed packages are safer than code fetched from the web |
| Exports for your AI | `output_docs/` | dated `.md` files you hand over yourself |
| Internal reports, quarantine | `~/.local/share/thek/` | sensitive data, kept outside the repository |

`vendor/` and `output_docs/` are in `.gitignore`: nothing in them is ever committed or published.

## Updating external components

Menu option **11 · Update external components** fetches Zero Breach Toolkit's published history,
shows the new commits and a change summary, and moves to the new version **only if you say yes**.
Then it offers to refresh the indicator lists. The version THEK pins on first download is the
one its authors reviewed; anything newer is your call.

## Using the report with your AI

THEK does not send the report anywhere. Menu option **12 · Export report for your AI** writes
the last report to `output_docs/thek-report-<date>_<time>-<redacted|full>.md` and prints its
path and a `cd` line to copy:

- **Redacted** (default, press Enter): without your user name, host name, home path, IPs, MACs,
  emails or SSH key comments. The one to use with cloud AIs (ChatGPT, Claude, Gemini…).
- **Full** (`f`): includes all of that. Only give it to an AI running on your own machine, or one
  you trust with that data.
- In both, secrets (tokens, keys) are cut short.

The file starts with instructions for the model: attach it or paste it into the chat as it is.

Terminal agents (Claude Code, Codex, Aider…) read [AGENTS.md](AGENTS.md): open one in this folder
and ask it to "analyze the last THEK report".

## Settings

All optional, all environment variables:

| Variable | Meaning |
|---|---|
| `THEK_LANG` | `es` or `en` |
| `THEK_SCAN_ROOTS` | extra folders for the secret search, separated by `:` |
| `NO_COLOR` | disable colors |

## Restoring a file from the quarantine

Each folder in `~/.local/share/thek/quarantine/` has a `manifest.json` with the original path:

```sh
mv ~/.local/share/thek/quarantine/<date>/000-file /original/path/file
chmod 644 /original/path/file
```

## Tests

```sh
python3 test_thek.py      # prints "ok"
sh tests/containers.sh        # every supported distro in podman containers
```

## Credits

THEK only orchestrates these projects; all the real work is theirs:
[ClamAV](https://www.clamav.net/) (GPL-2.0), [rkhunter](https://rkhunter.sourceforge.net/) (GPL-2.0),
[chkrootkit](https://www.chkrootkit.org/), [Lynis](https://cisofy.com/lynis/) (GPL-3.0) and
[Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) (Apache-2.0).

## License

MIT, see [LICENSE](LICENSE).
