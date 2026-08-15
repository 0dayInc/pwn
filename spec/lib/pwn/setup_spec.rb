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
end
