# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'timeout'
require 'pwn/setup'

# Guards documentation/Installation.md from silently rotting.
#
# Layer 1 — every table / code-block / claim in the doc is treated as an
#           assertion against the live gem (PWN::Setup constants + CLI
#           surface). Cheap, deterministic, runs on every `rake`.
#
# Layer 2 — behavioural contracts the doc PROMISES (`--dry-run` mutates
#           nothing, `--yes` never blocks on stdin, `--check` exit code,
#           profile isolation). Exercised in-process against PWN::Setup.
#
# Layer 3 — fresh-host provisioning — is NOT asserted here (an install
#           doc can only be proven on a box that doesn't already have
#           pwn). See .github/workflows/install-matrix.yml and
#           spec/integration/install_doc.sh.
RSpec.describe 'documentation/Installation.md' do
  repo_root = File.expand_path('../..', __dir__)
  doc_path  = File.join(repo_root, 'documentation', 'Installation.md')
  doc       = File.read(doc_path)

  # ------------------------------------------------------------------
  # Layer 1 — static doc ↔ code introspection
  # ------------------------------------------------------------------
  describe 'doc ↔ code parity' do
    it 'exists' do
      expect(File).to exist(doc_path)
    end

    it 'profile table matches PWN::Setup::PROFILES exactly' do
      # "| `core` | ... |" rows in the Capability profiles table
      doc_profiles = doc.scan(/^\| `(\w+)`\s+\|/).flatten.map(&:to_sym).uniq
      expect(doc_profiles).to match_array(PWN::Setup::PROFILES.keys)
    end

    it 'flag table matches bin/pwn_setup OptionParser' do
      help = `#{RbConfig.ruby} #{File.join(repo_root, 'bin/pwn_setup')} --help </dev/null 2>&1`
      %w[--check --deps --profile --list-profiles --yes --dry-run].each do |flag|
        expect(doc).to  include(flag), "doc missing flag #{flag}"
        expect(help).to include(flag), "bin/pwn_setup --help missing flag #{flag}"
      end
    end

    it 'documents every package manager PWN::Setup.pkg_manager can return' do
      %w[apt dnf pacman brew port].each do |pm|
        expect(doc).to include(pm)
        # every NATIVE_GEMS / TOOLCHAIN row must map that manager
        (PWN::Setup::NATIVE_GEMS.values + PWN::Setup::TOOLCHAIN.values).each do |row|
          expect(row).to have_key(pm.to_sym)
        end
      end
    end

    it 'programmatic API section is truthful' do
      expect(PWN::Setup).to respond_to(:check, :deps, :list_profiles, :pkg_manager)
      expect(PWN::Setup.check(io: StringIO.new).keys)
        .to eq(%i[ok native_gems_missing toolchain_missing pkg_manager os arch])
      expect(PWN::Setup.pkg_manager.keys).to eq(%i[key install sudo])
      expect(PWN::Setup.constants).to include(:NATIVE_GEMS, :TOOLCHAIN, :PROFILES)
    end

    it 'PROFILES only reference gems/bins that exist in NATIVE_GEMS / TOOLCHAIN' do
      PWN::Setup::PROFILES.each do |name, meta|
        Array(meta[:gems]).each do |g|
          expect(PWN::Setup::NATIVE_GEMS).to have_key(g), "profile :#{name} → unknown gem '#{g}'"
        end
        Array(meta[:bins]).each do |b|
          expect(PWN::Setup::TOOLCHAIN).to have_key(b), "profile :#{name} → unknown bin '#{b}'"
        end
      end
    end

    it 'all three invocation spellings are wired in bin/pwn' do
      pwn_bin = File.read(File.join(repo_root, 'bin/pwn'))
      expect(pwn_bin).to match(/ARGV\.first == 'setup'/)   # `pwn setup ...`
      expect(pwn_bin).to include('pwn_setup')              # → bin/pwn_setup
      expect(pwn_bin).to match(/--setup\[?=/)              # `pwn --setup[=PROFILE]`
    end

    it 'internal .md links resolve' do
      doc.scan(/\]\(([\w.-]+\.md)(?:#[\w-]+)?\)/).flatten.uniq.each do |f|
        expect(File).to exist(File.join(repo_root, 'documentation', f)), "broken link: #{f}"
      end
    end

    it 'legacy install.sh / packer provisioner delegate to `pwn setup` (as claimed)' do
      %w[install.sh packer/provisioners/pwn.sh].each do |f|
        path = File.join(repo_root, f)
        next unless File.exist?(path)

        expect(File.read(path)).to match(/pwn[ _]setup|PWN::Setup/),
                                   "#{f} does not delegate to `pwn setup` — doc claims it does"
      end
    end

    it 'gemspec ships bin/pwn_setup as an executable' do
      spec = Gem::Specification.load(File.join(repo_root, 'pwn.gemspec'))
      expect(spec.executables).to include('pwn_setup')
      expect(spec.executables).to include('pwn')
    end

    it '`pwn setup` and `pwn_setup` produce identical --list-profiles output' do
      a = `#{RbConfig.ruby} #{File.join(repo_root, 'bin/pwn')} setup --list-profiles </dev/null 2>&1`
      b = `#{RbConfig.ruby} #{File.join(repo_root, 'bin/pwn_setup')} --list-profiles </dev/null 2>&1`
      expect(a).to eq(b)
      PWN::Setup::PROFILES.each_key { |k| expect(a).to include(k.to_s) }
    end
  end

  # ------------------------------------------------------------------
  # Layer 2 — behavioural contracts the doc promises
  # ------------------------------------------------------------------
  describe 'behavioural contracts' do
    it '`--dry-run` never shells out (no system(), no gets())' do
      expect(PWN::Setup).not_to receive(:system)
      expect($stdin).not_to receive(:gets)
      r = PWN::Setup.deps(profile: :net, dry_run: true, io: StringIO.new)
      expect(r[:profile]).to eq(:net)
      expect(r[:ran]).to all(include(dry_run: true))
    end

    it '`yes: true` never reads stdin' do
      allow(PWN::Setup).to receive(:system).and_return(true)
      expect($stdin).not_to receive(:gets)
      Timeout.timeout(30) do
        PWN::Setup.deps(profile: :core, yes: true, dry_run: true, io: StringIO.new)
      end
    end

    it '`--profile X` only resolves packages from PROFILES[X]' do
      io = StringIO.new
      r  = PWN::Setup.deps(profile: :net, dry_run: true, io: io)
      # inspect the deps plan only (before the trailing doctor re-check)
      plan = io.string.split('Re-checking').first
      cmds = Array(r[:ran]).map { |h| h[:cmd] }.join(' ')
      pm   = PWN::Setup.pkg_manager[:key]
      # every :net bin's package appears in the plan
      PWN::Setup::PROFILES[:net][:bins].each do |b|
        Array(PWN::Setup::TOOLCHAIN.dig(b, pm)).each do |pkg|
          expect(plan).to include(pkg), "profile :net missing own package '#{pkg}'"
        end
      end
      # no :sdr-only bin's package leaks into the :net install commands
      (PWN::Setup::PROFILES[:sdr][:bins] - PWN::Setup::PROFILES[:net][:bins]).each do |b|
        Array(PWN::Setup::TOOLCHAIN.dig(b, pm)).each do |pkg|
          expect(cmds).not_to include(pkg), "profile :net leaked :sdr package '#{pkg}'"
        end
      end
    end

    it 'unknown profile raises with the list of known ones' do
      expect { PWN::Setup.deps(profile: :nope, io: StringIO.new) }
        .to raise_error(/Unknown profile 'nope'.*#{PWN::Setup::PROFILES.keys.join(', ')}/)
    end

    it 'check() report shape drives the documented exit code' do
      r = PWN::Setup.check(io: StringIO.new)
      expect([true, false]).to include(r[:ok])
      # bin/pwn_setup: `exit 1 unless r[:ok]` — assert that line still exists
      expect(File.read(File.join(repo_root, 'bin/pwn_setup')))
        .to match(/exit 1 unless r\[:ok\]/)
    end

    it 'list_profiles returns PROFILES.keys' do
      expect(PWN::Setup.list_profiles(io: StringIO.new)).to eq(PWN::Setup::PROFILES.keys)
    end
  end
end
