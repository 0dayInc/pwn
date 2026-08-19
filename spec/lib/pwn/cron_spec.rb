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
  describe 'OS-agnostic scheduler' do
    before do
      @tmp = Dir.mktmpdir('pwn-cron-os-spec-')
      stub_const('PWN::Cron::CRON_DIR', @tmp)
      stub_const('PWN::Cron::JOBS_FILE', File.join(@tmp, 'jobs.yml'))
      stub_const('PWN::Cron::PID_FILE', File.join(@tmp, 'worker.pid'))
      stub_const('PWN::Cron::WORKER_LOG', File.join(@tmp, 'worker.log'))
      ENV['PWN_CRON_DIR'] = @tmp
    end

    after do
      ENV.delete('PWN_CRON_DIR')
      FileUtils.remove_entry(@tmp) if @tmp && Dir.exist?(@tmp)
    end

    it 'exposes scheduler control methods' do
      %i[
        os_type scheduler_backend cron_to_calendar
        install_scheduler uninstall_scheduler sync_scheduler
        scheduler_status cron_enabled? persist_scheduler_config
      ].each do |m|
        expect(PWN::Cron).to respond_to(m)
      end
      expect(PWN::Cron::DEFAULT_JOBS.length).to eq(5)
      names = PWN::Cron::DEFAULT_JOBS.map { |j| j[:name] }
      expect(names).to include('pwn_stores_lean_nightly')
      expect(names).to include('learning_consolidate_nightly')
      enabled = PWN::Cron::DEFAULT_JOBS.reject { |j| j[:enabled] == false }.map { |j| j[:name] }
      expect(enabled).to contain_exactly('pwn_stores_lean_nightly', 'learning_consolidate_nightly')
    end

    it 'picks a native backend per OS without consulting live daemons' do
      expect(PWN::Cron.scheduler_backend(os: :osx)).to eq(:launchd)
      expect(PWN::Cron.scheduler_backend(os: :windows, backend: :schtasks)).to eq(:schtasks)
      expect(PWN::Cron.scheduler_backend(backend: :crontab)).to eq(:crontab)
      expect(%i[systemd_user crontab worker]).to include(
        PWN::Cron.scheduler_backend(os: :linux)
      )
      expect(%i[crontab worker]).to include(
        PWN::Cron.scheduler_backend(os: :freebsd)
      )
    end

    it 'maps the four default 5-field schedules to portable calendars' do
      expected = {
        '0 3 * * *' => { kind: :daily, minute: 0, hour: 3 },
        '0 4 * * 0' => { kind: :weekly, minute: 0, hour: 4, wday: 0 },
        '30 3 * * *' => { kind: :daily, minute: 30, hour: 3 },
        '0 5 * * *' => { kind: :daily, minute: 0, hour: 5 },
        '15 5 * * *' => { kind: :daily, minute: 15, hour: 5 }
      }
      PWN::Cron::DEFAULT_JOBS.each do |spec|
        cal = PWN::Cron.cron_to_calendar(schedule: spec[:schedule])
        expect(cal).to eq(expected[spec[:schedule]]), spec[:name]
      end
      expect(PWN::Cron.cron_to_calendar(schedule: 'every 30m')).to be_nil
      expect(PWN::Cron.systemd_on_calendar(schedule: '0 3 * * *')).to eq('*-*-* 03:00:00')
      expect(PWN::Cron.launchd_calendar_interval(schedule: '0 4 * * 0')).to eq(
        'Hour' => 4, 'Minute' => 0, 'Weekday' => 0
      )
      expect(PWN::Cron.schtasks_spec(schedule: '30 3 * * *')).to eq(
        sc: 'DAILY', st: '03:30'
      )
    end

    it 'install_scheduler(apply:false) writes preview units and persists enabled:true' do
      PWN::Cron.install_defaults
      res = PWN::Cron.install_scheduler(backend: :launchd, apply: false)
      expect(res[:ok]).to be true
      expect(res[:backend]).to eq(:launchd)
      expect(res[:apply]).to be false
      expect(PWN::Cron.cron_enabled?).to be true
      expect(PWN::Cron.scheduler_config[:backend]).to eq(:launchd)
      worker_plist = File.join(@tmp, 'native', "#{PWN::Cron::LAUNCHD_WORKER_LABEL}.plist")
      expect(File).to exist(worker_plist)
      body = File.read(worker_plist)
      expect(body).to include('<key>RunAtLoad</key>')
      expect(body).to include('<true/>')
      expect(body).to include('<key>KeepAlive</key>')
      PWN::Cron.list.each_value do |job|
        next unless job[:enabled]

        plist = File.join(@tmp, 'native', "com.0dayinc.pwn.cron.job.#{job[:id]}.plist")
        expect(File).to exist(plist)
        xml = File.read(plist)
        cal = PWN::Cron.launchd_calendar_interval(schedule: job[:schedule])
        expect(xml).to include("<integer>#{cal['Hour']}</integer>")
        expect(xml).to include("<integer>#{cal['Minute']}</integer>")
      end
    end

    it 'systemd backend emits OnCalendar that matches each default schedule' do
      PWN::Cron.install_defaults
      res = PWN::Cron.install_scheduler(backend: :systemd_user, apply: false)
      expect(res[:ok]).to be true
      expect(File).to exist(File.join(@tmp, 'native', PWN::Cron::SYSTEMD_WORKER_UNIT))
      unit = File.read(File.join(@tmp, 'native', PWN::Cron::SYSTEMD_WORKER_UNIT))
      expect(unit).to include('Restart=always')
      PWN::Cron.list.each_value do |job|
        next unless job[:enabled]

        tmr = File.join(@tmp, 'native', "pwn-cron-j#{job[:id]}.timer")
        expect(File).to exist(tmr)
        oncal = PWN::Cron.systemd_on_calendar(schedule: job[:schedule])
        expect(File.read(tmr)).to include("OnCalendar=#{oncal}")
      end
    end

    it 'crontab backend previews @reboot worker plus each 5-field line' do
      PWN::Cron.install_defaults
      res = PWN::Cron.install_scheduler(backend: :crontab, apply: false)
      expect(res[:ok]).to be true
      worker = File.read(File.join(@tmp, 'native', 'worker.crontab'))
      expect(worker).to include('@reboot')
      expect(worker).to include('PWN::Cron.ensure_worker')
      PWN::Cron.list.each_value do |job|
        next unless job[:enabled]

        preview = File.read(File.join(@tmp, 'native', "job-#{job[:id]}.crontab"))
        expect(preview).to include(job[:schedule])
        expect(preview).to include(job[:id])
      end
    end

    it 'schtasks backend previews ONLOGON worker plus DAILY/WEEKLY specs' do
      PWN::Cron.install_defaults
      weekly = PWN::Cron.create(name: 'weekly-on', schedule: '0 4 * * 0', ruby: '1', enabled: true)
      res = PWN::Cron.install_scheduler(backend: :schtasks, apply: false)
      expect(res[:ok]).to be true
      expect(File.read(File.join(@tmp, 'native', 'worker.schtasks.txt'))).to include('ONLOGON')
      txt = File.read(File.join(@tmp, 'native', "job-#{weekly[:id]}.schtasks.txt"))
      expect(txt).to include('WEEKLY')
      expect(txt).to include('SUN')
    end

    it 'uninstall_scheduler persists enabled:false and drops preview units' do
      PWN::Cron.install_defaults
      PWN::Cron.install_scheduler(backend: :launchd, apply: false)
      res = PWN::Cron.uninstall_scheduler(backend: :launchd, apply: false, stop: false)
      expect(res[:ok]).to be true
      expect(PWN::Cron.cron_enabled?).to be false
      expect(File).not_to exist(File.join(@tmp, 'native', "#{PWN::Cron::LAUNCHD_WORKER_LABEL}.plist"))
    end

    it 'disable then enable realigns native units with jobs.yml' do
      PWN::Cron.install_scheduler(backend: :systemd_user, apply: false)
      job = PWN::Cron.create(name: 'flip', schedule: '15 2 * * *', ruby: '1')
      tmr = File.join(@tmp, 'native', "pwn-cron-j#{job[:id]}.timer")
      expect(File).to exist(tmr)
      PWN::Cron.disable(id: job[:id])
      expect(File).not_to exist(tmr)
      PWN::Cron.enable(id: job[:id])
      expect(File).to exist(tmr)
      expect(File.read(tmr)).to include('OnCalendar=*-*-* 02:15:00')
    end
  end
end
