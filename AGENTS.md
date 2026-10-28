# Instructions for AI agents (Claude Code, Codex, Aider, …)

THEK audits the Linux machine it runs on and writes a report meant for you.

## Analyzing this machine

1. Run `python3 THEK_run.py --audit quick` (no root, no network). Exit code: 0 nothing found,
   2 something critical, 3 warnings or gaps.
2. Read `~/.local/share/thek/reports/latest/report.md` (`$XDG_DATA_HOME/thek/...` if set).
   It starts with instructions for you; follow them.
3. Older reports, ClamAV and spyware scans are in sibling folders of `latest`.
4. Exports the user made for an AI are in `output_docs/` in this repository (dated `.md` files,
   ignored by git).

`--audit full` needs root once (pkexec in a desktop session, sudo otherwise). Ask the user to run it
in their own terminal if you have no way to authenticate.

## Rules

- Propose; do not act. **Nothing that changes the system runs without the user's explicit
  confirmation** — packages, services, firewall, files, quarantine.
- Prefer THEK's own actions (ids listed at the end of every report; the user runs them from the
  menu) over ad-hoc commands.
- `UNAVAILABLE` means "could not be checked", never "clean".
- Never print, copy or ask for the value of a secret. Reports only keep a prefix on purpose.
- Do not edit the SSH server configuration on your own: a wrong edit can lock the user out.
- If anything suggests a targeted attack, recommend expert help
  (Access Now Digital Security Helpline: https://www.accessnow.org/help/).

## Working on THEK's code

- Python 3.9+, standard library only. `checks.py` reads and never mutates or touches the network;
  `actions.py` holds everything that mutates and always asks through `confirm()`.
- No `shell=True`. Root commands are literals in the code; user input only travels as list arguments.
- Run `python3 test_thek.py` before proposing a change; it also checks that the repository
  contains no personal data or secrets.
