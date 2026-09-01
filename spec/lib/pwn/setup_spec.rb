# frozen_string_literal: true

require 'spec_helper'

describe PWN::Setup do
  it 'should display information for authors' do
    authors_response = PWN::Setup
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Setup
    expect(help_response).to respond_to :help
  end

  it 'exposes the capability data tables' do
    expect(PWN::Setup::NATIVE_GEMS).to be_a(Hash)
    expect(PWN::Setup::TOOLCHAIN).to be_a(Hash)
    expect(PWN::Setup::PROFILES).to be_a(Hash)
    expect(PWN::Setup::PROFILES).to have_key(:full)
  end

  it 'detects a package manager without raising' do
    pm = PWN::Setup.pkg_manager
    expect(pm).to be_a(Hash)
    expect(pm).to have_key(:key)
  end

  it 'exposes ensure_cron to start the scheduler from pwn setup' do
    expect(PWN::Setup).to respond_to(:ensure_cron)
  end

  it 'ensure_cron seeds defaults and starts (or reuses) the worker' do
    tmp = Dir.mktmpdir('pwn-setup-cron-')
    stub_const('PWN::Cron::CRON_DIR', tmp)
    stub_const('PWN::Cron::JOBS_FILE', File.join(tmp, 'jobs.yml'))
    stub_const('PWN::Cron::PID_FILE', File.join(tmp, 'worker.pid'))
    stub_const('PWN::Cron::WORKER_LOG', File.join(tmp, 'worker.log'))
    ENV['PWN_CRON_DIR'] = tmp
    allow(PWN::Cron).to receive(:install_worker_crontab).and_return('stubbed')
    io = StringIO.new
    first = PWN::Setup.ensure_cron(restart: false, io: io)
    expect(first[:ok]).to be true
    expect(first[:worker][:running]).to be true
    pid = first[:worker][:pid]
    expect(pid).to be_a(Integer)
    second = PWN::Setup.ensure_cron(restart: false, io: StringIO.new)
    expect(second[:ok]).to be true
    expect(second[:worker][:pid] || second[:worker][:already_running]).to be_truthy
    # reuse: same pid still alive
    expect(second[:worker][:pid]).to eq(pid)
  ensure
    begin
      PWN::Cron.stop_worker
    rescue StandardError
      nil
    end
    ENV.delete('PWN_CRON_DIR')
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'ensure_cron dry_run does not spawn' do
    io = StringIO.new
    allow(PWN::Cron).to receive(:worker_status).and_return(
      running: false, pid: nil, pid_file: '/tmp/x', log: '/tmp/y'
    )
    res = PWN::Setup.ensure_cron(dry_run: true, io: io)
    expect(res[:dry_run]).to be true
    expect(res[:ok]).to be true
  end
  it 'ensure_cron enabled:false uninstalls the OS scheduler without spawning' do
    tmp = Dir.mktmpdir('pwn-setup-nocron-')
    stub_const('PWN::Cron::CRON_DIR', tmp)
    stub_const('PWN::Cron::JOBS_FILE', File.join(tmp, 'jobs.yml'))
    stub_const('PWN::Cron::PID_FILE', File.join(tmp, 'worker.pid'))
    stub_const('PWN::Cron::WORKER_LOG', File.join(tmp, 'worker.log'))
    ENV['PWN_CRON_DIR'] = tmp
    io = StringIO.new
    res = PWN::Setup.ensure_cron(enabled: false, apply: false, io: io)
    expect(res[:enabled]).to be false
    expect(res[:ok]).to be true
    expect(PWN::Cron.cron_enabled?).to be false
    again = PWN::Setup.ensure_cron(enabled: true, apply: false, io: StringIO.new, restart: false)
    expect(again[:enabled]).to be true
    expect(PWN::Cron.cron_enabled?).to be true
    expect(%i[systemd_user crontab launchd schtasks worker]).to include(again[:backend])
  ensure
    begin
      PWN::Cron.stop_worker
    rescue StandardError
      nil
    end
    ENV.delete('PWN_CRON_DIR')
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'bin/pwn_setup exposes --[no-]cron' do
    body = File.read(File.expand_path('../../../bin/pwn_setup', __dir__))
    expect(body).to include('--[no-]cron')
    expect(body).to include('cron_opts[:enabled] = opts[:cron]')
    expect(body.scan('PWN::Setup.ensure_cron').length).to eq(1)
    expect(body).to include('opts[:migrate] && running')
  end

  it 'TOOLCHAIN covers every plugin required_bins name' do
    plugin_bins = Dir[File.expand_path('../../../lib/pwn/plugins/*.rb', __dir__)].flat_map do |path|
      src = File.read(path)
      m = src.match(/public_class_method def self\.required_bins\n\s+%w\[([^\]]*)\]/)
      next [] unless m

      m[1].split
    end.uniq
    missing = plugin_bins - PWN::Setup::TOOLCHAIN.keys
    expect(missing).to eq([]), "pwn setup TOOLCHAIN missing plugin bins: #{missing.join(', ')}"
  end

  it 'every TOOLCHAIN row has an OS package or pip/gem installer' do
    PWN::Setup::TOOLCHAIN.each do |bin, meta|
      has_pkg = %i[apt dnf pacman brew port].any? { |k| Array(meta[k]).any? }
      has_alt = meta[:pip].to_s != '' || meta[:gem].to_s != ''
      expect(has_pkg || has_alt).to be(true), "#{bin} has no apt/dnf/pacman/brew/port/pip/gem installer"
    end
  end

  it 'deps --profile full dry-run emits pip/gem for unpackaged toolchain bins' do
    io = StringIO.new
    r = PWN::Setup.deps(profile: :full, dry_run: true, io: io)
    cmds = Array(r[:ran]).map { |h| h[:cmd] }.join("\n")
    expect(r[:skipped]).not_to be true
    unpackaged = PWN::Setup::TOOLCHAIN.select do |_bin, meta|
      %i[apt dnf pacman brew port].none? { |k| Array(meta[k]).any? }
    end
    unpackaged.each do |bin, meta|
      token = meta[:pip] || meta[:gem] || bin
      expect(cmds).to include(token.to_s), "full dry-run missing installer for #{bin} (#{token})"
    end
  end

  it 'packages_for prefers distro overrides then package-manager family' do
    expect(
      PWN::Setup.packages_for(bin: 'nmap', distro: :ubuntu, version: '24.04', pm_key: :apt)
    ).to eq(%w[nmap])
    expect(
      PWN::Setup.packages_for(bin: 'burpsuite', distro: :kali, version: '2026.3', pm_key: :apt)
    ).to eq(%w[burpsuite])
    expect(
      PWN::Setup.packages_for(bin: 'burpsuite', distro: :ubuntu, version: '24.04', pm_key: :apt)
    ).to eq([])
  end

  it 'deps skips kali-only apt packages on ubuntu' do
    io = StringIO.new
    r = PWN::Setup.deps(profile: :web, dry_run: true, io: io, distro: :ubuntu, version: '24.04')
    cmds = Array(r[:ran]).map { |h| h[:cmd] }.join(' ')
    expect(cmds).not_to include('burpsuite')
    expect(cmds).not_to include('zaproxy')
  end
end
