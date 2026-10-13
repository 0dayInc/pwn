# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'Bundled session cleanup' do
  include_context 'pwn tmp sandbox'

  it 'seeds a portable guarded daily job and helper only once' do
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
    original = PWN::Cron.create(name: 'session_cleanup', schedule: '12 9 * * *', ruby: 'custom guard', enabled: false)
    File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 7))
    result = PWN::Migrate.run(fix: false, backup: false, io: StringIO.new)
    expect(result[:applied_migrations]).to eq([8])
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
    expect(File.read(helper)).to include('# PWN managed default: session_cleanup v6')
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
    expect(JSON.parse(output)).to include('dry_run' => true, 'scanned' => 0, 'deleted_ids' => [])
  end
end
