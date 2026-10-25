#!/bin/bash
# Route the system fprintd through the vfs495 feeder daemon.
# Every file this creates is listed in docs/SYSTEM_CHANGES.md and removed by
# scripts/system_uninstall.sh. It changes no PAM/authselect/GDM configuration.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x target/release/vfs495 ] || { echo "build first: cargo build --release"; exit 1; }

install -D -m 0755 target/release/vfs495 /usr/local/bin/vfs495
# Install every populated per-model data dir (data/<model>/ is gitignored and
# generated with tools/ — see data/README.md). The daemon picks the model by USB ID.
installed_any=0
for d in data/*/; do
    [ -f "$d/capture_seq.json" ] || continue
    model=$(basename "$d")
    install -d -m 0700 "/usr/local/share/vfs495/data/$model/patches"
    for f in "$d"*.json "$d"*.hex "$d"*.bin; do
        [ -f "$f" ] && install -m 0600 "$f" "/usr/local/share/vfs495/data/$model/$(basename "$f")"
    done
    for f in "$d"patches/*; do
        [ -f "$f" ] && install -m 0600 "$f" "/usr/local/share/vfs495/data/$model/patches/$(basename "$f")"
    done
    installed_any=1
done
[ "$installed_any" = 1 ] || { echo "no populated data/<model>/ found — run tools/ first (see data/README.md)"; exit 1; }
chmod 0700 /usr/local/share/vfs495
install -D -m 0644 packaging/vfs495.service /etc/systemd/system/vfs495.service
install -D -m 0644 packaging/fprintd-vfs495.conf /etc/systemd/system/fprintd.service.d/vfs495.conf
restorecon -R /usr/local/bin/vfs495 /usr/local/share/vfs495 /etc/systemd/system/vfs495.service \
    /etc/systemd/system/fprintd.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl try-restart fprintd.service || true
systemctl enable vfs495.service
systemctl restart vfs495.service
echo "installed. Enroll with: fprintd-enroll   (swipe while the Caps Lock LED is lit)"
