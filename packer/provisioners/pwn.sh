#!/bin/bash --login
# packer/provisioners/pwn.sh
#
# Thin delegator to `pwn setup` (PWN::Setup) — the single, versioned-with-
# the-gem source of truth for OS packages / native-gem headers / external
# toolchain across apt · dnf · pacman · brew · port.
#
# The historical `case $os` + per-package `apt install` blocks that lived
# here have been consolidated into PWN::Setup::NATIVE_GEMS / ::TOOLCHAIN
# (lib/pwn/setup.rb). Every install path — gem, git checkout, Docker,
# Packer, Vagrant, CI — now reads the same data tables.
#
#   PWN_PROFILE  — capability profile to provision (default: full)
#                  one of: core ai web net db sdr vision voice exploit hardware full
#   PWN_ROOT     — git checkout to build/install from (optional; falls back
#                  to the already-installed gem if unset/absent)
#
# See documentation/Installation.md.
source /etc/profile.d/globals.sh 2>/dev/null || true
set -e

if [[ -z "${PWN_ROOT}" ]]; then
  if   [[ -d '/opt/pwn' ]]; then pwn_root='/opt/pwn'
  elif [[ -d '/pwn'     ]]; then pwn_root='/pwn'
  else pwn_root="$(pwd)"
  fi
else
  pwn_root="${PWN_ROOT}"
fi

pwn_profile="${PWN_PROFILE:-full}"
pwn_provider="${PWN_PROVIDER:-}"

echo "[pwn.sh] provider=${pwn_provider:-none} root=${pwn_root} profile=${pwn_profile}"

# ---------------------------------------------------------------------------
# 1. Ensure the `pwn` gem (and therefore `pwn setup` / PWN::Setup) is present.
#    Prefer building from the checkout so image builds track the repo HEAD;
#    fall back to rubygems.org when no checkout exists.
# ---------------------------------------------------------------------------
if ! command -v pwn >/dev/null 2>&1; then
  if [[ -f "${pwn_root}/pwn.gemspec" ]]; then
    echo "[pwn.sh] building & installing gem from ${pwn_root}"
    git config --global --add safe.directory "${pwn_root}" 2>/dev/null || true
    ( cd "${pwn_root}" && command -v bundle >/dev/null 2>&1 && bundle install && rake install ) \
      || ( cd "${pwn_root}" && gem build pwn.gemspec && gem install --no-document ./pwn-*.gem )
  else
    echo "[pwn.sh] no checkout at ${pwn_root}; installing from rubygems.org"
    gem install --no-document pwn
  fi
fi

# ---------------------------------------------------------------------------
# 2. Delegate ALL OS-level provisioning to PWN::Setup.
#    This replaces the old `case $(uname -s)` apt/port blocks entirely.
# ---------------------------------------------------------------------------
echo "[pwn.sh] pwn setup --profile ${pwn_profile} --yes"
pwn setup --profile "${pwn_profile}" --yes

# ---------------------------------------------------------------------------
# 3. Doctor — non-zero exit if any capability in the profile is degraded,
#    so packer / vagrant / CI fail loudly instead of shipping a broken image.
# ---------------------------------------------------------------------------
echo "[pwn.sh] pwn setup --check"
pwn setup --check
