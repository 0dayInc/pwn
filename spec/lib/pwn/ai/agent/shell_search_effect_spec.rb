# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/request_runtime'

describe 'finished shell searches do not block the answer' do
  include_context 'pwn tmp sandbox'

  it 'keeps a non-zero search exit as a failed observation' do
    runtime = PWN::AI::Agent::RequestRuntime.new(request: 'how does pwn-ai use tools configured with openwebUi?', session_id: 'search-exit', artifact_root: @tmp, trace: false)
    result = runtime.execute_tool(name: 'shell', args: { command: 'rg openwebui' }, effect: :exclusive, action_id: 'search') do
      { stdout: 'open_web_ui.rb', stderr: '', exit: 1 }
    end
    expect(result[:exit]).to eq(1)
    expect(runtime.events.last[:state]).to eq('failed')
    expect(runtime.blocker).to be_nil
    expect(runtime.unmet).to be_empty
    again = runtime.execute_tool(name: 'shell', args: { command: 'rg openwebui' }, effect: :exclusive, action_id: 'search-again') do
      { stdout: 'open_web_ui.rb', stderr: '', exit: 1 }
    end
    expect(again[:exit]).to eq(1)
  end

  it 'does not demand reconciliation for an interrupted non-write shell command' do
    runtime = PWN::AI::Agent::RequestRuntime.new(request: 'how does pwn-ai use tools configured with openwebUi?', session_id: 'search-interrupt', artifact_root: @tmp, trace: false)
    call = { name: 'shell', args: { command: 'rg openwebui' }, effect: :exclusive, action_id: 'search' }
    expect { runtime.execute_tool(call) { raise Timeout::Error } }.to raise_error(Timeout::Error)
    expect(runtime.blocker).to be_nil
    expect(runtime.unmet).to be_empty
    denied = runtime.execute_tool(call.merge(action_id: 'replay')) { raise 'replayed' }
    expect(denied[:error]).to eq('uncertain_side_effect')
  end

  it 'does not block the answer when a classified write returns permission denied' do
    runtime = PWN::AI::Agent::RequestRuntime.new(request: 'how does pwn-ai use tools configured with openwebUi?', session_id: 'write-denied', artifact_root: @tmp, trace: false)
    result = runtime.execute_tool(name: 'shell', args: { command: "python -c 'open(\"/tmp/server_tools.rb\",\"w\")'" }, effect: :write, action_id: 'denied-write') do
      { stdout: '', stderr: 'PermissionError: Permission denied: /tmp/server_tools.rb', exit: 1 }
    end
    expect(result[:exit]).to eq(1)
    expect(runtime.events.last[:state]).to eq('failed')
    expect(runtime.blocker).to be_nil
    expect(runtime.unmet).to be_empty
  end
end
