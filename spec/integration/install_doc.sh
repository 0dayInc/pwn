#!/usr/bin/env bash
# spec/integration/install_doc.sh
#
# Local runner for Layer 3 of the Installation.md verification strategy
# (fresh-host provisioning). Executes the doc's fenced bash blocks
# verbatim inside clean containers for every claimed distro / package
# manager, then asserts the result via **rspec** — the same
# spec/documentation/installation_md_spec.rb +
# spec/integration/fresh_install_spec.rb pair that
# .github/workflows/install-matrix.yml runs.
#
#   ./spec/integration/install_doc.sh                 # all distros, profile=core
#   PROFILE=net ./spec/integration/install_doc.sh
#   IMAGES="debian:bookworm fedora:latest" ./spec/integration/install_doc.sh
#   ENGINE=podman ./spec/integration/install_doc.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE="${ENGINE:-docker}"
PROFILE="${PROFILE:-core}"
IMAGES="${IMAGES:-kalilinux/kali-rolling debian:bookworm ubuntu:24.04 fedora:latest archlinux:latest}"

pass=(); fail=()

bootstrap_for() {
  case "$1" in
    kalilinux/*|debian:*|ubuntu:*) echo 'apt-get update && apt-get install -y ruby-full ruby-dev build-essential git' ;;
    fedora:*)                      echo 'dnf install -y ruby ruby-devel redhat-rpm-config gcc gcc-c++ make git' ;;
    archlinux:*)                   echo 'pacman -Sy --noconfirm ruby base-devel git' ;;
    *)                             echo 'true' ;;
  esac
}

pm_for() {
  case "$1" in
    kalilinux/*|debian:*|ubuntu:*) echo apt    ;;
    fedora:*)                      echo dnf    ;;
    archlinux:*)                   echo pacman ;;
    *)                             echo unknown;;
  esac
}

for img in $IMAGES; do
  echo
  echo "════════════════════════════════════════════════════════════════════"
  echo " $img  ·  profile=$PROFILE  ·  pm=$(pm_for "$img")"
  echo "════════════════════════════════════════════════════════════════════"
  boot="$(bootstrap_for "$img")"
  pm="$(pm_for "$img")"
  if "$ENGINE" run --rm -v "$REPO_ROOT":/src:ro \
       -e DEBIAN_FRONTEND=noninteractive \
       -e PWN_FRESH_INSTALL=1 \
       -e PWN_EXPECTED_PM="$pm" \
       -e PWN_PROFILE="$PROFILE" \
       "$img" bash -exc "
         $boot
         cp -r /src /opt/pwn && cd /opt/pwn
         gem build pwn.gemspec
         gem install --no-document ./pwn-*.gem
         gem install --no-document rspec
         pwn setup --profile full --dry-run --yes    # every pkg name resolves
         pwn setup --profile $PROFILE --yes           # Installation.md verbatim
         rspec --format documentation \
           spec/documentation/installation_md_spec.rb \
           spec/integration/fresh_install_spec.rb
       "; then
    pass+=("$img")
  else
    fail+=("$img")
  fi
done

echo
echo "──────────────────────────────────────────────────────────────────────"
echo " PASS (${#pass[@]}): ${pass[*]:-}"
echo " FAIL (${#fail[@]}): ${fail[*]:-}"
echo "──────────────────────────────────────────────────────────────────────"
[[ ${#fail[@]} -eq 0 ]]
