# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools job_run' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/job_run.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_run')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_status')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_result')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_tail')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_kill')).not_to be_nil
  end

  it 'forwards a six-hour runtime independently of dispatch timeout accounting' do
    expect(PWN::Plugins::Jobs).to receive(:start).with(hash_including(command: 'printf scan', max_runtime: 21_600, cwd: '/tmp', idempotency_key: 'campaign-one')).and_return(id: '012345abcdef', status: 'RUNNING')
    ledger = {}
    response = JSON.parse(PWN::AI::Agent::Dispatch.call(
                            tool_call: { function: { name: 'job_run', arguments: { command: 'printf scan', max_runtime: 21_600, cwd: '/tmp', idempotency_key: 'campaign-one' } } },
                            budget_ledger: ledger
                          ))
    expect(response.dig('result', 'id')).to eq('012345abcdef')
    expect(response).not_to have_key('budget')
    expect(ledger).to be_empty
  end

  it 'tails by byte cursor with a bounded page and lets a new session discover jobs' do
    reader = PWN::AI::Agent::Registry.lookup(name: 'job_tail')
    expect(PWN::Plugins::Jobs).to receive(:tail).with(hash_including(id: '012345abcdef', offset: 17, length: PWN::AI::Agent::Result.page_length)).and_return(next_offset: 23, body: 'output')
    expect(reader.handler.call(id: '012345abcdef', offset: 17, length: 50_000_000)).to include(next_offset: 23)
    expect(PWN::Plugins::Jobs).to receive(:list).with(limit: 20).and_return([{ id: '012345abcdef' }])
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_status').handler.call({})).to include(id: '012345abcdef')
  end

  it 'routes predicted long shell work before Dispatch injects a blocking timeout' do
    allow(PWN::AI::Agent::ToolGuard).to receive(:auto_job?).with(payload: 'printf slow').and_return(true)
    expect(PWN::Plugins::Jobs).to receive(:start).with(hash_including(command: 'printf slow')).and_return(id: '012345abcdef', status: 'RUNNING')
    ledger = {}
    out = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'shell', arguments: { command: 'printf slow' } } }, budget_ledger: ledger))
    expect(out.dig('result', 'id')).to eq('012345abcdef')
    expect(ledger).to be_empty
  end

  it 'runs a real serialized launch with environment overrides and incrementally retrieves its result' do
    Dir.mktmpdir('pwn-job-tool-') do |root|
      stub_const('PWN::Plugins::Jobs::JOBS_DIR', root)
      invoke = lambda do |name, args|
        JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: name, arguments: JSON.generate(args) } }), symbolize_names: true)
      end
      launched = invoke.call('job_run', command: 'printf "$PWN_JOB_TEST"', env: { PWN_JOB_TEST: 'supervised-output' }, max_runtime: 5, cwd: root)
      id = launched.fetch(:result).fetch(:id)
      Timeout.timeout(10) do
        loop do
          state = invoke.call('job_status', id: id).fetch(:result)
          break if state[:status] != 'RUNNING'

          sleep 0.05
        end
      end
      expect(invoke.call('job_status', id: id).fetch(:result)).to include(status: 'COMPLETED', exit_code: 0)
      page = invoke.call('job_tail', id: id, offset: 0).fetch(:result)
      expect(page).to include(body: 'supervised-output', next_offset: 17)
      expect(invoke.call('job_tail', id: id, offset: page[:next_offset]).dig(:result, :bytes)).to eq(0)
    end
  end
end
