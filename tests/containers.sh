#!/bin/sh
# Runs THEK on every supported distro family in podman containers:
# self-tests, --doctor, quick audit with no network, and --install (confirms package names).
# Usage: sh tests/containers.sh [distro ...]     (default: all)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
LOGS=$(mktemp -d "${TMPDIR:-/tmp}/thek-containers.XXXXXX")

image_of() {
    case "$1" in
        debian)   echo docker.io/library/debian:12 ;;
        ubuntu)   echo docker.io/library/ubuntu:24.04 ;;
        fedora)   echo registry.fedoraproject.org/fedora:44 ;;
        arch)     echo docker.io/library/archlinux:latest ;;
        opensuse) echo registry.opensuse.org/opensuse/tumbleweed:latest ;;
        rocky)    echo docker.io/rockylinux/rockylinux:9 ;;
    esac
}

python_install() {
    case "$1" in
        debian|ubuntu) echo "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null" ;;
        fedora|rocky)  echo "dnf install -y -q python3" ;;
        arch)          echo "pacman -Sy --noconfirm --needed python >/dev/null" ;;
        opensuse)      echo "zypper -n -q in python3" ;;
    esac
}

DISTROS=${*:-debian ubuntu fedora arch opensuse rocky}
RUN="podman run --rm -e PYTHONDONTWRITEBYTECODE=1 -e THEK_LANG=en -v $HERE:/thek:ro"

printf '%-9s | %-5s | %-6s | %-13s | %s\n' distro tests doctor "audit offline" "missing after --install"
for d in $DISTROS; do
    img=$(image_of "$d")
    tag="localhost/thek-test:$d"
    log="$LOGS/$d.log"
    if ! podman image exists "$tag"; then
        if ! podman run --name "thek-prep-$d" "$img" sh -c "$(python_install "$d")" >"$log" 2>&1; then
            podman rm -f "thek-prep-$d" >/dev/null 2>&1
            printf '%-9s | could not prepare the image (see %s)\n' "$d" "$log"
            continue
        fi
        podman commit -q "thek-prep-$d" "$tag" >/dev/null && podman rm "thek-prep-$d" >/dev/null
    fi

    $RUN "$tag" python3 /thek/test_thek.py >>"$log" 2>&1 && tests=ok || tests=FAIL
    $RUN "$tag" python3 /thek/THEK_run.py --doctor >>"$log" 2>&1 && doctor=ok || doctor=FAIL

    $RUN --network=none --timeout 120 "$tag" python3 /thek/THEK_run.py --audit quick >"$LOGS/$d.audit" 2>&1
    code=$?
    cat "$LOGS/$d.audit" >>"$log"
    case "$code" in 0|2|3) audit="ok ($code)" ;; *) audit="FAIL ($code)" ;; esac
    grep -q Traceback "$LOGS/$d.audit" && audit="FAIL (traceback)"

    missing=$($RUN "$tag" sh -c "printf 's\n' | python3 /thek/THEK_run.py --install; python3 /thek/THEK_run.py --doctor" 2>&1 \
        | tee -a "$log" | awk '/^  (clamscan|freshclam|rkhunter|chkrootkit|lynis|debsums) +- /{print $1}' | tr '\n' ' ')
    printf '%-9s | %-5s | %-6s | %-13s | %s\n' "$d" "$tests" "$doctor" "$audit" "${missing:-none}"
done
echo "logs: $LOGS"
