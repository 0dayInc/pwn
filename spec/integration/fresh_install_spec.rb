# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'pwn/setup'

# Layer 3 of the Installation.md verification strategy — functional
# assertions that only make sense on a *freshly-provisioned* host
# (a container / CI runner that just ran `gem install pwn && pwn setup`).
#
# These examples are gated behind PWN_FRESH_INSTALL so that a
# developer's `rake` on an already-provisioned workstation does not
# execute them; they are driven by .github/workflows/install-matrix.yml
# and spec/integration/install_doc.sh which set:
#
#   PWN_FRESH_INSTALL=1
#   PWN_EXPECTED_PM=apt|dnf|pacman|brew|port   (which column of
#                                               NATIVE_GEMS/TOOLCHAIN
#                                               this leg proves)
#   PWN_PROFILE=core|net|...                   (which profile was
#                                               provisioned and must
#                                               now be fully satisfied)
#
RSpec.describe 'fresh-host install (documentation/Installation.md §Layer 3)',
               if: ENV.fetch('PWN_FRESH_INSTALL', nil) do
  let(:expected_pm) { ENV.fetch('PWN_EXPECTED_PM').to_sym }
  let(:profile)     { ENV.fetch('PWN_PROFILE', 'core').to_sym }
  let(:report)      { PWN::Setup.check(io: StringIO.new) }

  it 'PWN::VERSION loads and reports the running platform' do
    expect(PWN::VERSION).to match(/\A\d+\.\d+\.\d+\z/)
    puts "pwn #{PWN::VERSION} · ruby #{RUBY_VERSION} · #{RUBY_PLATFORM} · " \
         "pkg-manager=#{PWN::Setup.pkg_manager[:key]}"
  end

  it 'detects the package manager the CI matrix leg claims' do
    expect(PWN::Setup.pkg_manager[:key]).to eq(expected_pm)
  end

  it 'every NATIVE_GEMS / TOOLCHAIN row maps this package manager' do
    (PWN::Setup::NATIVE_GEMS.values + PWN::Setup::TOOLCHAIN.values).each do |row|
      expect(row).to have_key(expected_pm)
    end
  end

  it '`pwn setup --profile full --dry-run` resolves every package name' do
    io = StringIO.new
    r  = PWN::Setup.deps(profile: :full, dry_run: true, yes: true, io: io)
    expect(r[:ran]).to all(include(dry_run: true))
    expect(io.string).not_to match(/\bnil\b/), 'unmapped package for this distro'
  end

  it 'the provisioned profile is fully satisfied (doctor gate)' do
    need  = PWN::Setup::PROFILES.fetch(profile)
    gems  = report[:native_gems_missing] & Array(need[:gems])
    bins  = report[:toolchain_missing]   & Array(need[:bins])
    expect(gems).to be_empty, "profile :#{profile} degraded — gems: #{gems.inspect}"
    expect(bins).to be_empty, "profile :#{profile} degraded — bins: #{bins.inspect}"
  end

  it '`pwn setup`, `pwn_setup` and `pwn --setup` are all wired' do
    a = `pwn setup   --list-profiles </dev/null 2>&1`
    b = `pwn_setup   --list-profiles </dev/null 2>&1`
    expect(a).to eq(b)
    PWN::Setup::PROFILES.each_key { |k| expect(a).to include(k.to_s) }
    expect(`pwn --help </dev/null 2>&1`).to include('--setup')
  end

  it '`pwn setup --check` exit status matches report[:ok]' do
    system('pwn', 'setup', '--check', in: File::NULL, out: File::NULL, err: File::NULL)
    expect($CHILD_STATUS.exitstatus).to eq(report[:ok] ? 0 : 1)
  end
end
