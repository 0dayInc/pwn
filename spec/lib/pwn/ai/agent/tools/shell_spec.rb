# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools shell' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/shell.rb'
  end

  let(:handler) do
    entry = PWN::AI::Agent::Registry.lookup(name: 'shell')
    expect(entry).not_to be_nil
    entry.handler
  end

  it 'registers the shell tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'shell')).not_to be_nil
  end

  # Holdouts for mistakes 30e55df3a6d6 / 853b3ca24b9e (shell syntax error: \)
  it 'strips a trailing backslash so sh does not see syntax error: \\' do
    r = handler.call(command: 'echo hello\\')
    expect(r[:error]).to be_nil
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s).to include('hello')
  end

  it 'joins mid-command backslash-newline continuations into a space' do
    r = handler.call(command: "echo hello\\\nworld")
    expect(r[:error]).to be_nil
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s.gsub(/\s+/, ' ').strip).to eq('hello world')
  end

  it 'still runs printf with embedded escapes in single quotes' do
    r = handler.call(command: "printf '%s\\n' hi")
    expect(r[:error]).to be_nil
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s).to include('hi')
  end

  it 'runs a plain command unchanged' do
    r = handler.call(command: 'echo holdout_ok_30e55')
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s).to include('holdout_ok_30e55')
  end

  it 'blocks unauthorized hping3 subnet sweep style commands' do
    Thread.current[:pwn_recon_authorized] = false
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :recon_authorized).and_return(nil)
    r = handler.call(command: 'hping3 -1 -c 1 192.168.1.1')
    expect(r[:error]).to eq('unauthorized_recon_blocked')
    expect(r[:exit]).to eq(126)
    expect(r[:stderr].to_s).to match(/blocked unauthorized recon/)
  ensure
    Thread.current[:pwn_recon_authorized] = nil
  end

  it 'allows commands when recon_authorized thread flag is set' do
    Thread.current[:pwn_recon_authorized] = true
    r = handler.call(command: 'echo allowed_hping_guard')
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s).to include('allowed_hping_guard')
  ensure
    Thread.current[:pwn_recon_authorized] = nil
  end
end
