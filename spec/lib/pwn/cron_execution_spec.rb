# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Cron execution outcomes' do
  include_context 'pwn tmp sandbox'

  before do
    allow(PWN::Cron).to receive(:sync_one_job)
    allow(PWN::Cron).to receive(:native_execution?).and_return(false)
  end

  it 'reports a failed script as an error rather than a successful job' do
    path = File.join(@tmp, 'failed-script')
    File.write(path, "#!/bin/sh\nprintf 'fixture failure\\n'\nexit 23\n")
    File.chmod(0o700, path)
    job = PWN::Cron.create(script: path, sync_native: false)
    result = PWN::Cron.run(id: job[:id])
    expect(result).to include(status: 'error', result: "fixture failure\n")
    expect(PWN::Cron.list[job[:id]][:last_status]).to eq('error')
  end

  it 'executes a literal script path containing spaces and shell metacharacters' do
    path = File.join(@tmp, 'fixture ; false')
    File.write(path, "#!/bin/sh\nprintf 'literal fixture\\n'\n")
    File.chmod(0o700, path)
    job = PWN::Cron.create(script: path, sync_native: false)
    expect(PWN::Cron.run(id: job[:id])).to include(status: 'success', result: "literal fixture\n")
  end

  it 'routes prompt jobs to the configured Open WebUI provider' do
    PWN::Env[:ai][:active] = :openwebui
    allow(PWN::AI::OpenWebUI).to receive(:chat).with(request: 'fixture prompt', spinner: false).and_return(choices: [{ content: 'fixture response' }])
    job = PWN::Cron.create(prompt: 'fixture prompt', sync_native: false)
    expect(PWN::Cron.run(id: job[:id])).to include(status: 'success', result: 'fixture response')
    expect(PWN::AI::OpenWebUI).to have_received(:chat).once
  end

  it 'catches a monthly slot after more than a week of downtime' do
    expect(PWN::Cron.due?(schedule: '0 5 15 * *', last_run: Time.local(2026, 5, 1), now: Time.local(2026, 5, 20))).to be(true)
    expect(PWN::Cron.due?(schedule: '0 5 15 * *', last_run: Time.local(2026, 5, 15, 5), now: Time.local(2026, 5, 20))).to be(false)
  end

  it 'matches either day field when both cron day-of-month and weekday are restricted' do
    # 2026-05-18 is a Monday, but it is not the first of the month.
    now = Time.local(2026, 5, 18, 5)
    expect(PWN::Cron.due?(schedule: '0 5 1 * 1', last_run: now - 60, now: now)).to be(true)
  end

  it 'matches Sunday represented by seven inside cron ranges' do
    now = Time.local(2026, 5, 17, 5)
    expect(now.wday).to eq(0)
    expect(PWN::Cron.due?(schedule: '0 5 * * 5-7', last_run: now - 60, now: now)).to be(true)
    expect(PWN::Cron.due?(schedule: '0 5 * * 5-7/2', last_run: now - 60, now: now)).to be(true)
  end

  it 'uses the same instant regardless of the supplied current-time offset' do
    [Time.local(2026, 5, 18, 4, 59), Time.local(2026, 5, 18, 5)].each do |now|
      shifted = now.getlocal(now.utc_offset.zero? ? '+01:00' : '+00:00')
      expected = now.hour == 5
      expect(PWN::Cron.due?(schedule: '0 5 18 5 *', last_run: now - 60, now: now)).to be(expected)
      expect(PWN::Cron.due?(schedule: '0 5 18 5 *', last_run: now - 60, now: shifted)).to be(expected)
    end
  end

  it 'does not report startup success when the child PID is no longer alive' do
    allow(PWN::Cron).to receive(:worker_status).and_return(running: false)
    allow(PWN::Cron).to receive(:read_pid).and_return(12_345)
    allow(PWN::Cron).to receive(:process_alive?).with(pid: 12_345).and_return(false)
    allow(PWN::Cron).to receive(:sleep)
    allow(Process).to receive(:spawn).and_return(12_345)
    allow(Process).to receive(:detach)
    expect(PWN::Cron.start_worker(restart: false)).to include(started: false)
  end
end
