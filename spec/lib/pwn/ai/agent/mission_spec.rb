# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::Mission do
  let(:tmp) { Dir.mktmpdir('pwn-mission-') }

  before do
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(tmp, 'missions'))
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/shell.rb'
  end

  after do
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'persists the original request and resumes the bound DAG without re-inferring steps' do
    described_class.begin!(id: 'lab', request: 'scan then record')
    log = File.join(tmp, 'log.txt')
    dag = {
      'request' => 'scan then record',
      'approved' => true,
      'steps' => [
        { 'id' => 's1', 'tool' => 'shell', 'args' => { 'command' => "printf first >> #{log}" }, 'side_effect' => 'read_only', 'dependencies' => [] },
        { 'id' => 's2', 'tool' => 'shell', 'args' => { 'command' => "printf second >> #{log}" }, 'side_effect' => 'read_only', 'dependencies' => ['s1'] }
      ]
    }
    first = PWN::AI::Agent::TaskDAG.execute(dag: dag, approved: true, halt_after: 's1', root: tmp, run_id: 'lab-run')
    described_class.bind_run!(id: 'lab', run_id: first[:run_id], root: tmp)
    report = described_class.resume_run(id: 'lab')
    expect(report[:resumed]).to eq(true)
    expect(report[:results].map { |row| row[:id] }).to eq(['s2'])
    expect(File.read(log)).to eq('firstsecond')
    expect(described_class.current(id: 'lab')[:last_completed_step]).to eq('s2')
  end

  it 'does not mark a named-duration mission done before the clock elapses' do
    described_class.begin!(id: 'long', request: 'fuzz for 6 hours', min_seconds: 21_600)
    expect(described_class.done?(id: 'long')).to eq(false)
  end

  it 'refuses an unattended inferred shell DAG that was not approved' do
    expect do
      PWN::AI::Agent::TaskDAG.execute(
        dag: { 'steps' => [{ 'id' => 's1', 'tool' => 'shell', 'args' => { 'command' => 'true' }, 'dependencies' => [] }] },
        unattended: true,
        root: tmp,
        run_id: 'nope'
      )
    end.to raise_error(ArgumentError, /approved/)
  end

  it 'records a LOST job as an unknown outcome, not success' do
    described_class.begin!(id: 'lab', request: 'scan then record')
    report = described_class.record_lost(id: 'lab', jobs: [{ id: 'job1', status: 'LOST' }])
    expect(report[:success]).to eq(false)
    expect(report[:lost]).to eq(['job1'])
    expect(described_class.done?(id: 'lab')).to eq(false)
  end

  it 'writes done only when checkpoints, duration, and requested evidence are present' do
    described_class.begin!(id: 'lab', request: 'record findings then loot')
    dag = {
      'steps' => [
        { 'id' => 's1', 'tool' => 'shell', 'args' => { 'command' => 'true' }, 'dependencies' => [] }
      ]
    }
    run = PWN::AI::Agent::TaskDAG.execute(dag: dag, approved: true, root: tmp, run_id: 'lab-run')
    described_class.bind_run!(id: 'lab', run_id: run[:run_id], root: tmp)
    blocked = described_class.complete!(id: 'lab')
    expect(blocked[:ok]).to eq(false)
    described_class.note_finding!(id: 'lab', finding_id: 'f1')
    described_class.note_loot!(id: 'lab', handle: 'loot1')
    done = described_class.complete!(id: 'lab')
    expect(done[:ok]).to eq(true)
    expect(described_class.current(id: 'lab')[:status]).to eq('done')
  end

  it 'keeps both evidence notes when two writers update the same mission' do
    described_class.begin!(id: 'lab', request: 'record findings')
    threads = %w[f1 f2].map do |fid|
      Thread.new { described_class.note_finding!(id: 'lab', finding_id: fid) }
    end
    threads.each(&:join)
    expect(described_class.current(id: 'lab')[:finding_ids]).to include('f1', 'f2')
  end

  it 'reattaches an idempotent LOST job and does not treat it as success' do
    described_class.begin!(id: 'lab', request: 'scan')
    described_class.note_job!(id: 'lab', job_id: 'job9', idempotent: true, log_offset: 12, command: 'true')
    allow(PWN::Plugins::Jobs).to receive(:status).with(id: 'job9').and_return(id: 'job9', status: 'LOST')
    report = described_class.recover!(id: 'lab')
    expect(report[:success]).to eq(false)
    expect(report[:reattach]).to eq(['job9'])
    expect(described_class.current(id: 'lab')[:lost_jobs]).to eq([])
  end

  it 'reports a live supervisor without reading the job log' do
    described_class.begin!(id: 'lab', request: 'scan')
    described_class.note_job!(id: 'lab', job_id: 'job9', idempotent: false, command: 'true')
    log = File.join(tmp, 'secret-tail.txt')
    File.write(log, 'TAIL_SHOULD_NOT_ENTER_LEDGER')
    allow(PWN::Plugins::Jobs).to receive(:status).with(id: 'job9').and_return(id: 'job9', status: 'RUNNING', log: log)
    expect(described_class.busy?(id: 'lab')).to eq(true)
    expect(described_class.ledger_text(id: 'lab')).to include('job9')
    expect(described_class.ledger_text(id: 'lab')).not_to include('TAIL_SHOULD_NOT_ENTER_LEDGER')
  end
end
