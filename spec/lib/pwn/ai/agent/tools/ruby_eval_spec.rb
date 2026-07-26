# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe 'PWN::AI::Agent::Tools ruby_eval' do
  before(:all) do
    PWN::AI::Agent::Registry.discover
  end

  it 'registers the pwn_eval tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')).not_to be_nil
  end

  it 'returns structured error for SyntaxError payloads (constant block param)' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    result = entry.handler.call(code: 'results = probes.map do |R|')
    expect(result).to be_a(Hash)
    expect(result[:error]).to match(/SyntaxError/)
    expect(result[:error]).to match(/\(pwn_eval\)/)
    expect(result[:error]).not_to match(/ruby_eval\.rb:49/)
    expect(result[:hint]).to match(/\|r\| not \|R\|/)
  end

  it 'evaluates valid code and returns stdout + value' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    result = entry.handler.call(code: '1 + 1')
    expect(result[:error]).to be_nil
    expect(result[:value]).to eq('2')
  end

  it 'Dispatch.call JSON-wraps syntax errors instead of raising' do
    out = PWN::AI::Agent::Dispatch.call(
      tool_call: {
        id: 't1',
        type: 'function',
        function: {
          name: 'pwn_eval',
          arguments: JSON.generate(code: 'results = probes.map do |R|')
        }
      }
    )
    parsed = JSON.parse(out, symbolize_names: true)
    # handler now rescues → success:true with error key in result
    expect(parsed[:success]).to eq(true)
    expect(parsed[:result][:error]).to match(/SyntaxError/)
  end
end
