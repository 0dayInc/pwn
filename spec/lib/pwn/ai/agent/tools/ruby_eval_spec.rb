# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

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

  it 'keeps locals across pwn_eval calls so a browser_obj can be reused' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    first = entry.handler.call(code: 'pwn_eval_persist_probe = 41')
    expect(first[:error]).to be_nil
    second = entry.handler.call(code: 'pwn_eval_persist_probe + 1')
    expect(second[:error]).to be_nil
    expect(second[:value]).to eq('42')
  end

  it 'restores HTTP if the payload assigns a path to the HTTP constant' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    path = File.join(Dir.mktmpdir, 'http')
    result = entry.handler.call(code: "HTTP = #{path.inspect}")
    expect(result[:error]).to be_nil
    expect(HTTP).to be_a(Module)
    expect { HTTP::CookieJar }.not_to raise_error
  end

  it 'restores Digest if the payload assigns Digest so later payload_sig still hashes' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    result = entry.handler.call(code: 'Digest = "(self.we"')
    expect(result[:error]).to be_nil
    expect(Digest).to be_a(Module)
    expect(Digest::SHA256.hexdigest('x')).to be_a(String)
    a = PWN::AI::Agent::Loop.send(:payload_sig, name: 'pwn_eval', args: '{"code":"1"}')
    b = PWN::AI::Agent::Loop.send(:payload_sig, name: 'pwn_eval', args: '{"code":"2"}')
    expect(a).not_to eq(b)
    expect(a).not_to match(/nosig-/)
    expect(b).not_to match(/nosig-/)
  end

  it 'enforces a timeout on pwn_eval and reports timeout after Ns' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
    entry = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')
    schema = entry.schema
    expect(schema.dig(:parameters, :properties, :timeout)).not_to be_nil
    t0 = Time.now
    result = entry.handler.call(code: 'sleep 3', timeout: 1)
    expect(Time.now - t0).to be < 2.5
    expect(result[:error].to_s).to match(/timeout after 1s/)
    expect(result[:hint].to_s).to match(/timeout \+= 180|next_timeout|same .*payload/i)
    expect(result[:scenario].to_s).to eq('deadline')
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
