# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'Bundled session cleanup' do
  include_context 'pwn tmp sandbox'

  it 'builds and installs the package into an isolated gem home for fresh and schema-10 upgrade paths' do
    package = File.join(@tmp, 'pwn.gem')
    repository = File.expand_path('../../..', __dir__)
    output, error, built = Open3.capture3(RbConfig.ruby, '-S', 'gem', 'build', 'pwn.gemspec', '--output', package, chdir: repository)
    expect(built.success?).to be(true), "#{output}\n#{error}"
    gem_home = File.join(@tmp, 'gems')
    env = { 'HOME' => File.join(@tmp, 'installed-home'), 'GEM_HOME' => gem_home,
            'GEM_PATH' => [gem_home, *Gem.path].join(File::PATH_SEPARATOR), 'RUBYOPT' => nil, 'BUNDLE_GEMFILE' => nil,
            'PWN_CRON_DIR' => File.join(@tmp, 'installed-home', '.pwn', 'cron') }
    FileUtils.mkdir_p(env['HOME'])
    output, error, installed = Open3.capture3(env, RbConfig.ruby, '-S', 'gem', 'install', '--local', package, '--ignore-dependencies', '--no-document', '--install-dir', gem_home)
    expect(installed.success?).to be(true), "#{output}\n#{error}"
    script = <<~RUBY
      require 'pwn'
      require 'json'
      require 'stringio'
      raise 'wrong gem activated' unless Gem.loaded_specs.fetch('pwn').full_gem_path.start_with?(ENV.fetch('GEM_HOME'))
      PWN::Cron.install_defaults
      jobs = File.binread(PWN::Cron.jobs_file)
      PWN::Cron.install_defaults
      raise 'non-idempotent jobs' unless File.binread(PWN::Cron.jobs_file) == jobs
      policy = File.join(Dir.home, '.pwn', 'maintenance', 'policy.json')
      config = JSON.parse(File.read(policy)).merge('batch_size' => 7)
      File.write(policy, JSON.generate(config))
      File.write(PWN::Migrate::SCHEMA_FILE, JSON.generate(schema: 10))
      upgrade = PWN::Migrate.run(fix: false, backup: false, io: StringIO.new)
      raise 'missing upgrade' unless upgrade[:applied_migrations] == [11]
      raise 'overwritten policy' unless JSON.parse(File.read(policy))['batch_size'] == 7
      raise 'non-idempotent upgrade' unless PWN::Migrate.run(fix: false, backup: false, io: StringIO.new)[:applied_migrations].empty?
      raise 'wrong helper' unless File.read(File.join(PWN::Cron.cron_dir, 'session_cleanup.rb')).include?('session_cleanup v10')
      report = PWN::SessionCleanup.status
      raise 'wrong inventory' unless report[:categories].length == 9
      # Exercise the installed startup request and original next-slot guard.
      configured = PWN::Cron.list
      configured.each_value { |job| job[:enabled] = false unless job[:name] == 'session_cleanup' }
      File.write(PWN::Cron.jobs_file, YAML.dump(configured))
      tick = PWN::Cron.tick
      raise 'startup failed' unless tick.length == 1 && tick.first[:status] == 'success'
      raise 'startup guard bypassed' unless Dir.glob(File.join(Dir.home, '.pwn', 'maintenance', 'runs', '*.json')).empty?
      raise 'startup not coalesced' unless PWN::Cron.tick.empty?
      # Actual installed producer, with only external analysis transport replaced.
      binary = File.join(Dir.home, 'fixture.bin')
      File.binwrite(binary, 'fixture binary')
      PWN::Plugins::Ghidra.define_singleton_method(:analyze) do |_opts = {}|
        { stdout: 'fixture analysis', exit: 0 }
      end
      PWN::Plugins::Ghidra.decompile(bin: binary)
      raise 'installed cache miss' unless PWN::Plugins::Ghidra.decompile(bin: binary)[:cached]
      sid = PWN::Sessions.create[:id]
      release = File.join(Dir.home, 'release-job')
      command = "while [ ! -f \#{release} ]; do sleep 0.05; done; printf fixture-complete"
      begin
        job = PWN::Plugins::Jobs.start(command: command, session_id: sid, cwd: Dir.home, max_runtime: 20)
        raise 'job not running' unless PWN::Plugins::Jobs.status(id: job[:id])[:status] == 'RUNNING'
        maintenance = PWN::SessionCleanup.coordinate(dry_run: false)
        raise 'missing coordinator phases' unless maintenance[:phases].keys == %i[maintenance memory_consolidation learning_retention mistakes_retention policy_retention]
        raise 'active job session deleted' unless File.file?(File.join(PWN::Sessions.sessions_dir, sid + '.jsonl'))
        raise 'job dependency omitted' unless PWN::Sessions.dependency_index[:dependencies].fetch(sid).any? { |path| path.include?('/jobs/') }
        File.write(release, 'release')
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
        while PWN::Plugins::Jobs.status(id: job[:id])[:status] == 'RUNNING'
          raise 'job did not finish' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          sleep 0.02
        end
        raise 'job outcome changed' unless PWN::Plugins::Jobs.status(id: job[:id])[:status] == 'COMPLETED'
      ensure
        File.write(release, 'release')
        PWN::Plugins::Jobs.stop(id: job[:id]) if job && PWN::Plugins::Jobs.status(id: job[:id])[:status] == 'RUNNING'
      end
      puts JSON.generate(installed: true, schema: PWN::Migrate.installed_schema, categories: report[:categories].keys)
    RUBY
    output, error, ran = Open3.capture3(env, RbConfig.ruby, '-e', script, chdir: @tmp)
    expect(ran.success?).to be(true), "#{output}\n#{error}"
    expect(JSON.parse(output)).to include('installed' => true, 'schema' => 11)
  end

  it 'never seeds curriculum on fresh install, upgrade or repeated migration after deletion' do
    PWN::Cron.install_defaults
    expect(PWN::Cron.list.values.map { |row| row[:name] }).not_to include('curriculum_practice_nightly', 'curriculum_train_weekly', 'curriculum_offline_judge')
    PWN::Cron::CURRICULUM_JOBS.each do |spec|
      job = PWN::Cron.create(spec.merge(sync_native: false))
      PWN::Cron.remove(id: job[:id], sync_native: false)
    end
    custom = PWN::Cron.create(name: 'custom-curriculum', ruby: '42', enabled: false, sync_native: false)
    File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 7))
    2.times { PWN::Migrate.run(fix: false, backup: false, io: StringIO.new) }
    expect(PWN::Cron.list.values.map { |row| row[:name] }).to contain_exactly('session_cleanup', 'custom-curriculum')
    expect(PWN::Cron.list.fetch(custom[:id])).to eq(custom)
  end

  it 'coordinates evidence-first maintenance, memory consolidation and retention exactly once' do
    require_relative '../../../etc/default_cron/session_cleanup'
    allow(Dir).to receive(:home).and_return(@tmp)
    FileUtils.mkdir_p(PWN::Sessions.sessions_dir)
    cleanup = PWN::SessionCleanup
    expect(cleanup).to receive(:maintain).with(dry_run: false, current_session_id: 'active', proc_root: '/proc').ordered.and_return(state: 'committed')
    expect(PWN::AI::Agent::Learning).to receive(:consolidate).once.ordered.and_return(removed: 0)
    expect(PWN::AI::Agent::Learning).to receive(:prune_outcomes!).with(dry_run: false).once.ordered.and_return(removed: 0)
    expect(PWN::AI::Agent::Mistakes).to receive(:lean!).with(dry_run: false).once.ordered.and_return(removed: 0)
    expect(PWN::AI::Agent::Policy).to receive(:lean!).with(dry_run: false).once.ordered.and_return(removed: 0)
    expect(PWN::AI::Agent::Learning).not_to receive(:gc_stores!)
    result = cleanup.coordinate(dry_run: false, current_session_id: 'active')
    expect(result[:phases].keys).to eq(%i[maintenance memory_consolidation learning_retention mistakes_retention policy_retention])
  end

  it 'keeps blocked coordinator phases nonapplying' do
    require_relative '../../../etc/default_cron/session_cleanup'
    allow(Dir).to receive(:home).and_return(@tmp)
    FileUtils.mkdir_p(PWN::Sessions.sessions_dir)
    allow(PWN::SessionCleanup).to receive(:maintain).and_return(apply_blocked: true, state: 'blocked')
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    expect(PWN::AI::Agent::Learning).not_to receive(:prune_outcomes!)
    expect(PWN::AI::Agent::Mistakes).not_to receive(:lean!)
    expect(PWN::AI::Agent::Policy).not_to receive(:lean!)
    expect(PWN::SessionCleanup.coordinate[:state]).to eq('blocked')
  end

  it 'never applies retention during coordinator previews and rejects duplicate maintenance owners' do
    require_relative '../../../etc/default_cron/session_cleanup'
    allow(Dir).to receive(:home).and_return(@tmp)
    FileUtils.mkdir_p(PWN::Sessions.sessions_dir)
    allow(PWN::SessionCleanup).to receive(:maintain).and_return(state: 'planned')
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    expect(PWN::AI::Agent::Learning).to receive(:prune_outcomes!).with(dry_run: true).once.and_return({})
    expect(PWN::AI::Agent::Mistakes).to receive(:lean!).with(dry_run: true).once.and_return({})
    expect(PWN::AI::Agent::Policy).to receive(:lean!).with(dry_run: true).once.and_return({})
    expect(PWN::SessionCleanup.coordinate(dry_run: true)[:state]).to eq('planned')
    expect(Dir.exist?(File.join(@tmp, '.pwn', 'maintenance', 'runs'))).to be(false)
    PWN::SessionCleanup.send(:with_maintenance_lock, dry_run: false) do
      thread = Thread.new do
        expect { PWN::SessionCleanup.coordinate }.to raise_error(IOError, /already running/)
      end
      expect(thread.join(2)).to eq(thread)
      thread.value
    end
  end

  it 'preserves legacy maintenance jobs and avoids adding duplicate retention phases' do
    legacy = PWN::Cron.create(name: 'learning_consolidate_nightly', ruby: 'custom', enabled: false, sync_native: false)
    PWN::Cron.install_defaults
    expect(PWN::Cron.list.fetch(legacy[:id])).to eq(legacy)
    job = PWN::Cron.list.values.find { |row| row[:name] == 'session_cleanup' }
    expect(job[:ruby]).to include('SessionCleanup.maintain(')
    expect(job[:ruby]).not_to include('SessionCleanup.coordinate(')
  end

  it 'installs housekeeping defaults without overwriting policy edits' do
    PWN::Cron.install_defaults
    path = File.join(File.dirname(PWN::Cron.cron_dir), 'maintenance', 'policy.json')
    expect(File.file?(path)).to be(true)
    value = JSON.parse(File.read(path))
    value['batch_size'] = 3
    File.write(path, JSON.generate(value))
    PWN::Cron.install_defaults
    expect(JSON.parse(File.read(path))['batch_size']).to eq(3)
  end

  it 'seeds a portable guarded daily job and helper only once' do
    allow(PWN::Cron).to receive(:systemd_user_available?).and_return(true)
    expect(PWN::Cron).not_to receive(:install_native_job)
    expect(PWN::Cron).not_to receive(:install_scheduler)
    PWN::Cron.install_defaults
    jobs = PWN::Cron.list.values.select { |job| job[:name] == 'session_cleanup' }
    expect(jobs.length).to eq(1)
    expect(jobs.first).to include(schedule: '45 3 * * *', enabled: true, last_run: nil)
    helper = File.join(PWN::Cron.cron_dir, 'session_cleanup.rb')
    expect(File).to exist(helper)
    expect(File.read(helper)).to eq(File.read(File.expand_path('../../../etc/default_cron/session_cleanup.rb', __dir__)))
    expect(PWN::Cron.run(id: jobs.first[:id])[:result]).to include(deferred: true, deleted: 0)
    bytes = File.read(PWN::Cron.jobs_file)
    PWN::Cron.install_defaults
    expect(File.read(PWN::Cron.jobs_file)).to eq(bytes)
  end

  it 'upgrades schema 7 and preserves an existing job identity, schedule and payload' do
    allow(PWN::Cron).to receive(:systemd_user_available?).and_return(true)
    expect(PWN::Cron).not_to receive(:install_native_job)
    expect(PWN::Cron).not_to receive(:install_scheduler)
    original = PWN::Cron.create(name: 'session_cleanup', schedule: '12 9 * * *', ruby: 'custom guard', enabled: false)
    File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 7))
    result = PWN::Migrate.run(fix: false, backup: false, io: StringIO.new)
    expect(result[:applied_migrations]).to eq([8, 9, 10, 11])
    expect(PWN::Cron.list.fetch(original[:id])).to eq(original)
    expect(PWN::Cron.list.values.count { |job| job[:name] == 'session_cleanup' }).to eq(1)
    expect(File).to exist(File.join(PWN::Cron.cron_dir, 'session_cleanup.rb'))
    bytes = File.read(PWN::Cron.jobs_file)
    expect(PWN::Migrate.run(fix: false, backup: false, io: StringIO.new)[:applied_migrations]).to eq([])
    expect(File.read(PWN::Cron.jobs_file)).to eq(bytes)
  end

  it 'refreshes managed helpers without modifying an existing job or scheduler drop-ins' do
    PWN::Cron.install_defaults
    helper = File.join(PWN::Cron.cron_dir, 'session_cleanup.rb')
    File.write(helper, "# PWN managed default: session_cleanup v0\n")
    bytes = File.read(PWN::Cron.jobs_file)
    expect(PWN::Cron).not_to receive(:install_native_job)
    PWN::Cron.install_defaults
    expect(File.read(helper)).to include('# PWN managed default: session_cleanup v10')
    expect(File.read(PWN::Cron.jobs_file)).to eq(bytes)
  end

  it 'preserves custom helpers and refuses symlink replacement' do
    helper = File.join(PWN::Cron.cron_dir, 'session_cleanup.rb')
    File.write(helper, '# custom helper')
    PWN::Cron.install_defaults
    expect(File.read(helper)).to eq('# custom helper')
    File.unlink(helper)
    destination = File.join(@tmp, 'operator-file')
    File.write(destination, 'keep')
    File.symlink(destination, helper)
    expect(PWN::Cron).to receive(:warn).with(/symlinked/)
    PWN::Cron.install_defaults
    expect(File.symlink?(helper)).to be(true)
    expect(File.read(destination)).to eq('keep')
  end

  it 'loads the shipped standalone helper in a fresh Ruby process without provider configuration' do
    PWN::Cron.install_defaults
    helper = File.join(PWN::Cron.cron_dir, 'session_cleanup.rb')
    output, error, status = Open3.capture3(
      { 'HOME' => File.join(@tmp, 'home'), 'PWN_CRON_DIR' => PWN::Cron.cron_dir },
      RbConfig.ruby, '-I', File.expand_path('../../../lib', __dir__), helper, '--dry-run'
    )
    expect(status.success?).to be(true), error
    expect(JSON.parse(output)).to include('dry_run' => true, 'scanned' => 0, 'deleted' => 0)
  end
end
