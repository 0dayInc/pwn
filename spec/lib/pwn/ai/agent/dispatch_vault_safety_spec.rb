# frozen_string_literal: true

require 'spec_helper'
require 'json'

RSpec.describe PWN::AI::Agent::Dispatch, 'vault access safety' do
  before do
    @calls = []
    @result = { status: 'fixture-complete' }
    handler = lambda do |args|
      @calls << args
      @result
    end
    entry = PWN::AI::Agent::Registry::Entry.new(name: 'vault_fixture', schema: { parameters: { type: 'object' } }, handler: handler)
    allow(PWN::AI::Agent::Registry).to receive(:lookup).with(name: 'vault_fixture').and_return(entry)
    allow(PWN::AI::Agent::Manifest).to receive(:load).and_return({})
    allow(PWN::AI::Agent::Manifest).to receive(:check).and_return(nil)
    allow(PWN::AI::Agent::ToolGuard).to receive_messages(scope_check!: nil, policy_decision: nil, canary_leak?: false, refuse_copied_persist?: false)
    allow(PWN::AI::Agent::Engagement).to receive(:deny_if_out_of_scope).and_return(nil)
    allow(PWN::AI::Agent::Mission).to receive(:active).and_return(nil)
    allow(PWN::AI::Agent::Confirmation).to receive(:gate).and_return(nil)
    allow(PWN::Plugins::Vault).to receive(:expand) { |opts| opts[:text] }
    allow(PWN::Plugins::Vault).to receive(:redact) { |opts| opts[:text] }
  end

  it 'expands nested vault references once per leaf before invoking the handler' do
    allow(PWN::Plugins::Vault).to receive(:expand).with(text: '{{vault:fixture}}').and_return('fixture-unlocked')
    arguments = { nested: [{ secret: '{{vault:fixture}}' }], slot: 2 }
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: arguments } }))
    expect(response['success']).to be(true)
    expect(@calls).to eq([{ nested: [{ secret: 'fixture-unlocked' }], slot: 2 }])
    expect(PWN::Plugins::Vault).to have_received(:expand).with(text: '{{vault:fixture}}').once
    expect(arguments[:nested].first[:secret]).to eq('{{vault:fixture}}')
  end

  it 'blocks a nested vault access failure without exposing its exception text' do
    allow(PWN::Plugins::Vault).to receive(:expand).with(text: '{{vault:fixture}}').and_raise(IOError, 'fixture-private-detail')
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: { nested: ['{{vault:fixture}}'] } } }))
    expect(response).to include('success' => false, 'code' => 'VAULT_EXPANSION_FAILED')
    expect(@calls).to be_empty
    expect(response.to_s).not_to include('fixture-private-detail')
  end

  it 'withholds results when vault output redaction fails after handler execution' do
    allow(PWN::Plugins::Vault).to receive(:redact).and_raise(IOError, 'fixture-private-detail')
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: {} } }))
    expect(@calls.length).to eq(1)
    expect(response).to include('success' => false, 'code' => 'VAULT_REDACTION_FAILED', 'handler_executed' => true)
    expect(response.to_s).not_to include('fixture-private-detail', 'fixture-complete')
    expect(response).not_to have_key('result')
  end

  it 'redacts secrets in array results such as loot offers before returning them' do
    @result = [{ secret: 'fixture-private-value' }]
    allow(PWN::Plugins::Vault).to receive(:redact) { |opts| opts[:text].gsub('fixture-private-value', '{{vault:fixture}}') }
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: {} } }))
    expect(response).to include('success' => true, 'result' => [{ 'secret' => '{{vault:fixture}}' }])
    expect(response.to_s).not_to include('fixture-private-value')
  end

  it 'blocks a real hardware-envelope expansion when the offline device fixture fails' do
    Dir.mktmpdir('pwn-dispatch-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      allow(PWN::AI::Agent::Mission).to receive(:active_id).and_return(nil)
      device = double('offline YubiKey fixture')
      stub_const('PWN::Plugins::YubiKey', device)
      allow(device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge)) }
      PWN::Plugins::Vault.store(label: 'fixture', secret: 'fixture-private-value', yubikey: { slot: 2 })
      allow(PWN::Plugins::Vault).to receive(:expand).and_call_original
      allow(device).to receive(:challenge_response).and_raise(IOError, 'fixture-private-detail')
      response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: { password: '{{vault:fixture}}' } } }))
      expect(response).to include('success' => false, 'code' => 'VAULT_EXPANSION_FAILED')
      expect(@calls).to be_empty
      expect(response.to_s).not_to include('fixture-private-detail', 'fixture-private-value')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
    end
  end

  it 'never invokes a real handler after expansion of a vault argument fails' do
    allow(PWN::Plugins::Vault).to receive(:expand).with(text: '{{vault:fixture}}').and_raise(IOError, 'device absent; fixture-private-detail')
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'vault_fixture', arguments: { password: '{{vault:fixture}}' } } }))
    expect(@calls).to be_empty
    expect(response).to include('success' => false, 'code' => 'VAULT_EXPANSION_FAILED')
    expect(response.to_s).not_to include('fixture-private-detail')
  end
end
