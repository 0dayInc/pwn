# frozen_string_literal: true

require 'spec_helper'
require 'timeout'
require File.expand_path('../../../etc/default_cron/session_cleanup', __dir__)

RSpec.describe PWN::SessionCleanup, 'concurrent maintenance' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
    @processes = File.join(@tmp, 'processes')
    FileUtils.mkdir_p(@processes)
    @children = []
  end

  after do
    @children.each do |pid, input, output|
      input.close unless input.closed?
      output.close unless output.closed?
      Timeout.timeout(5) { Process.wait(pid) }
    rescue Timeout::Error
      Process.kill('KILL', pid)
      Process.wait(pid)
    rescue Errno::ECHILD
      nil
    end
  end

  def worker(&block)
    reader, output = IO.pipe
    input, writer = IO.pipe
    pid = fork do
      reader.close
      writer.close
      @children.each do |_, old_input, old_output|
        old_input.close
        old_output.close
      end
      $0 = 'pwn-ai'
      block.call(input, output)
      exit! 0
    rescue Exception => e # rubocop:disable Lint/RescueException -- communicate child assertion failures
      output.puts("ERROR: #{e.class}: #{e.message}")
      exit! 1
    end
    input.close
    output.close
    @children << [pid, writer, reader]
    File.symlink("/proc/#{pid}", File.join(@processes, pid.to_s))
    [writer, reader]
  end

  def message(reader)
    raise 'Child did not respond before deadline' unless reader.wait_readable(10)

    reader.gets&.strip
  end

  def maintain
    Timeout.timeout(5) { described_class.maintain(proc_root: @processes) }
  end

  it 'retains two real active clients, deletes unrelated work and revisits released evidence' do
    ids = 3.times.map { PWN::Sessions.create[:id] }
    learning = PWN::AI::Agent::Learning
    File.write(learning::LEARNING_FILE, "#{JSON.generate(session_id: ids.first, lesson: 'résumé 日本語')}\n")
    clients = ids.first(2).map do |id|
      worker do |input, output|
        lease = PWN::Sessions.activate(session_id: id)
        output.puts('ready')
        input.gets
        PWN::Sessions.append(session_id: id, role: 'assistant', content: 'final 日本語 evidence')
        PWN::Sessions.deactivate(lease: lease)
        output.puts('released')
        input.gets
      end
    end
    clients.each { |client| expect(message(client.last)).to eq('ready') }
    expect(described_class.legacy_owners(@processes)).to eq([])
    first = maintain
    expect(first[:deleted_ids]).to eq([ids.last])
    expect(first[:evidence_migration][:deferred_active_sessions]).to eq(1)
    expect(JSON.parse(File.read(learning::LEARNING_FILE))).not_to have_key('evidence_ref')
    ids.first(2).each { |id| expect(File).to exist(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl")) }
    clients.each do |input, output|
      input.puts('release')
      expect(message(output)).to eq('released')
    end
    second = maintain
    expect(second[:deleted_ids]).to match_array(ids.first(2))
    expect(learning.session_evidence(session_id: ids.first).last[:content]).to eq('final 日本語 evidence')
    expect(second[:evidence_migration][:migrated_rows]).to eq(1)
  end

  it 'defers promptly behind a real learning writer and retries without losing its write' do
    id = PWN::Sessions.create[:id]
    learning = PWN::AI::Agent::Learning
    input, output = worker do |commands, replies|
      PWN::Sessions.send(:register_activity_owner)
      lock = learning.send(:learning_lock)
      replies.puts('locked')
      commands.gets
      File.write(learning::LEARNING_FILE, "#{JSON.generate(session_id: id, lesson: 'preserved 日本語')}\n")
      learning.send(:learning_unlock, lock: lock)
      replies.puts('written')
      commands.gets
    end
    expect(message(output)).to eq('locked')
    result = maintain
    expect(result[:evidence_migration]).to include(deferred: 'learning_writer_active', migrated_rows: 0)
    expect(result[:apply_blocked]).to be(true)
    expect(File).to exist(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl"))
    input.puts('write')
    expect(message(output)).to eq('written')
    expect(maintain[:deleted_ids]).to eq([id])
    expect(JSON.parse(File.read(learning::LEARNING_FILE))['lesson']).to eq('preserved 日本語')
    expect(learning.session_evidence(session_id: id)).not_to be_empty
  end

  it 'retains a real provider-blocked title worker without delaying unrelated cleanup' do
    id = PWN::Sessions.create[:id]
    other = PWN::Sessions.create[:id]
    PWN::Sessions.append(session_id: id, role: 'user', content: 'Title fixture topic')
    input, output = worker do |commands, replies|
      allow(PWN::AI::Router).to receive(:summarize) do
        replies.puts('provider entered')
        commands.gets
        JSON.generate(title: 'Fixture conversation summary', summary: 'Offline provider fixture summary')
      end
      PWN::Sessions.refresh_title(session_id: id)
      replies.puts('titled')
      commands.gets
    end
    expect(message(output)).to eq('provider entered')
    expect(described_class.legacy_owners(@processes)).to eq([])
    expect(maintain[:deleted_ids]).to eq([other])
    input.puts('finish provider')
    expect(message(output)).to eq('titled')
    expect(PWN::Sessions.title_status(session_id: id)[:is_summarized]).to be(true)
    expect(maintain[:deleted_ids]).to eq([])
  end

  it 'serializes two real outcome writers with repeated maintenance and preserves every row' do
    learning = PWN::AI::Agent::Learning
    clients = 2.times.map do |index|
      worker do |commands, replies|
        PWN::Sessions.send(:register_activity_owner)
        replies.puts('ready')
        commands.gets
        5.times { |turn| learning.note_outcome(task: "concurrent fixture #{index}/#{turn}", success: true) }
        replies.puts('written')
        commands.gets
      end
    end
    clients.each { |client| expect(message(client.last)).to eq('ready') }
    clients.each { |client| client.first.puts('start') } # rubocop:disable Style/CombinableLoops -- release only after both children are ready
    3.times { maintain }
    clients.each { |client| expect(message(client.last)).to eq('written') }
    maintain
    rows = File.readlines(learning::LEARNING_FILE).map { |line| JSON.parse(line) }
    expect(rows.length).to eq(10)
    expect(rows.map { |row| row.fetch('task') }.uniq.length).to eq(10)
  end

  it 'admits only one real maintenance owner and leaves a retry possible' do
    id = PWN::Sessions.create[:id]
    input, output = worker do |commands, replies|
      PWN::Sessions.send(:register_activity_owner)
      described_class.send(:with_maintenance_lock, dry_run: false) do
        replies.puts('locked')
        commands.gets
      end
      replies.puts('released')
      commands.gets
    end
    expect(message(output)).to eq('locked')
    expect { maintain }.to raise_error(IOError, /maintenance already running/)
    expect(File).to exist(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl"))
    input.puts('release')
    expect(message(output)).to eq('released')
    expect(maintain[:deleted_ids]).to eq([id])
  end

  it 'does not mistake a genuinely untracked real client for a cooperating owner' do
    id = PWN::Sessions.create[:id]
    _, output = worker do |commands, replies|
      PWN::Sessions.instance_variable_get(:@activity_owners)&.each_value { |file| file.close unless file.closed? }
      replies.puts('legacy')
      commands.gets
    end
    expect(message(output)).to eq('legacy')
    expect(described_class.legacy_owners(@processes)).to include(hash_including(reason: 'legacy_session_ownership_unknown'))
    result = maintain
    expect(result[:apply_blocked]).to be(true)
    expect(result[:deleted_ids]).to eq([])
    expect(File).to exist(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl"))
  end
end
