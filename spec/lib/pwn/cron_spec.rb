# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'time'

describe PWN::Cron do
  it 'should display information for authors' do
    authors_response = PWN::Cron
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Cron
    expect(help_response).to respond_to :help
  end

  describe 'in-process scheduler' do
    before do
      @tmp = Dir.mktmpdir('pwn-cron-spec-')
      stub_const('PWN::Cron::CRON_DIR', @tmp)
      stub_const('PWN::Cron::JOBS_FILE', File.join(@tmp, 'jobs.yml'))
      stub_const('PWN::Cron::PID_FILE', File.join(@tmp, 'worker.pid'))
      stub_const('PWN::Cron::WORKER_LOG', File.join(@tmp, 'worker.log'))
    end

    after do
      begin
        PWN::Cron.stop_worker
      rescue StandardError
        nil
      end
      FileUtils.remove_entry(@tmp) if @tmp && Dir.exist?(@tmp)
    end

    it 'exposes worker control methods' do
      %i[
        due? due_jobs run_due tick worker_loop
        start_worker stop_worker worker_status ensure_worker
        jobs_file pid_file worker_log
      ].each do |m|
        expect(PWN::Cron).to respond_to(m)
      end
    end

    it 'treats a never-run relative schedule as due and a recent one as not due' do
      expect(PWN::Cron.due?(schedule: 'every 1m', last_run: nil)).to be true
      expect(
        PWN::Cron.due?(schedule: 'every 1m', last_run: Time.now.utc.iso8601)
      ).to be false
      expect(
        PWN::Cron.due?(
          schedule: 'every 30s',
          last_run: (Time.now - 45).utc.iso8601
        )
      ).to be true
    end

    it 'marks a 5-field cron job due when last_run missed the slot' do
      now = Time.local(2026, 8, 14, 14, 12, 0)
      last = Time.utc(2026, 7, 26, 1, 32, 11)
      expect(
        PWN::Cron.due?(schedule: '0 5 * * *', last_run: last, now: now)
      ).to be true
      expect(
        PWN::Cron.due?(
          schedule: '0 3 * * *',
          last_run: Time.utc(2026, 8, 14, 9, 0, 5),
          now: now
        )
      ).to be false
    end

    it 'tick fires a due ruby job and advances last_run' do
      job = PWN::Cron.create(name: 'tick-me', schedule: 'every 1s', ruby: '2 + 2')
      expect(job[:last_run]).to be_nil
      fired = PWN::Cron.tick
      expect(fired.map { |r| r[:id] }).to include(job[:id])
      expect(fired.first[:status]).to eq('success')
      reloaded = PWN::Cron.list[job[:id]]
      expect(reloaded[:last_run]).not_to be_nil
      expect(reloaded[:last_status]).to eq('success')
    end

    it 'tick skips a job that is not yet due' do
      job = PWN::Cron.create(name: 'fresh', schedule: 'every 1h', ruby: '1')
      PWN::Cron.run(id: job[:id])
      last = PWN::Cron.list[job[:id]][:last_run]
      expect(PWN::Cron.tick).to eq([])
      expect(PWN::Cron.list[job[:id]][:last_run]).to eq(last)
    end

    it 'worker_loop once:true is a single tick' do
      PWN::Cron.create(name: 'once', schedule: 'every 1s', ruby: '3')
      expect(PWN::Cron.worker_loop(once: true)).to be true
      job = PWN::Cron.list.values.find { |j| j[:name] == 'once' }
      expect(job[:last_run]).not_to be_nil
    end

    it 'start_worker(restart:false) reuses a live worker' do
      allow(PWN::Cron).to receive(:worker_status).and_return(
        running: true,
        pid: 12_345,
        pid_file: PWN::Cron.pid_file,
        log: PWN::Cron.worker_log
      )
      res = PWN::Cron.start_worker(restart: false)
      expect(res[:already_running]).to be true
      expect(res[:started]).to be false
      expect(res[:pid]).to eq(12_345)
    end

    it 'spawns a background worker that fires a due job and advances last_run' do
      marker = File.join(@tmp, 'fired.txt')
      job = PWN::Cron.create(
        name: 'bg-fire',
        schedule: 'every 1s',
        ruby: "File.write(#{marker.inspect}, Time.now.utc.iso8601)"
      )
      ENV['PWN_CRON_DIR'] = @tmp
      begin
        res = PWN::Cron.start_worker(interval: 1, restart: true)
        expect(res[:started]).to be(true), "worker did not start: #{res.inspect} log=#{begin
          File.read(PWN::Cron.worker_log)
        rescue StandardError
          'none'
        end}"
        expect(PWN::Cron.worker_status[:running]).to be true
        deadline = Time.now + 8
        last = nil
        while Time.now < deadline
          last = PWN::Cron.list[job[:id]][:last_run]
          break if last && File.exist?(marker)

          sleep 0.2
        end
        expect(last).not_to be_nil
        expect(File).to exist(marker)
      ensure
        ENV.delete('PWN_CRON_DIR')
        PWN::Cron.stop_worker
        expect(PWN::Cron.worker_status[:running]).to be false
      end
    end

    it 'ensure_worker delegates to start_worker' do
      allow(PWN::Cron).to receive(:start_worker).and_return(started: true, pid: 99)
      res = PWN::Cron.ensure_worker(interval: 30)
      expect(PWN::Cron).to have_received(:start_worker).with(
        interval: 30,
        restart: false,
        foreground: false
      )
      expect(res[:started]).to be true
    end
  end
end
