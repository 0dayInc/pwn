# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh dispatch encryption' do
  let(:mesh_env) do
    {
      transport: 'mqtt',
      dispatch_to_pwn_ai: true,
      ai_whitelist: ['LongFast'],
      channel: {
        active: 'LongFast',
        LongFast: { psk: 'cHdu', region: 'US/UT', topic: '2/e/#', channel_num: 8 }
      }
    }
  end

  before do
    PWN::Env[:plugins] ||= {}
    @prev_mesh = PWN::Env[:plugins][:meshtastic]
    @prev_ai = PWN::Env[:ai]
    PWN::Env[:plugins][:meshtastic] = mesh_env
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:active] = 'ollama'
    %i[MeshDispatchLock MeshObj].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
  end

  after do
    PWN::Env[:plugins][:meshtastic] = @prev_mesh if PWN::Env[:plugins].is_a?(Hash)
    PWN::Env[:ai] = @prev_ai if defined?(PWN::Env)
    %i[MeshDispatchLock MeshObj].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
  end

  def dispatch(opts)
    described_class.send(
      :mesh_maybe_dispatch_to_pwn_ai,
      {
        from: '!abcabcab',
        to: '!ffffffff',
        channel_name: 'LongFast'
      }.merge(opts)
    )
  end

  it 'does not dispatch pwn-ai when the source channel uses a public PSK' do
    mesh_env[:channel][:LongFast][:psk] = 'AQ=='
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    expect(dispatch(text: '@ai hello on public')).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'does not dispatch pwn-ai for DMs unless the channel is on ai_whitelist' do
    mesh_env[:ai_whitelist] = []
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    expect(dispatch(text: '@ai hello in dm', to: '!00000b0b')).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'dispatches pwn-ai for DMs that reside on an encrypted whitelisted channel when the text starts with @ai' do
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai dm reply')
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    expect(dispatch(text: '@ai hello in dm', to: '!00000b0b')).to eq(:dispatched)
    expect(PWN::AI::Agent::Loop).to have_received(:run).with(
      hash_including(request: 'hello in dm', nested: true, engine: :ollama)
    )
    expect(described_class).to have_received(:mesh_send_text).with(
      hash_including(to: '!abcabcab', text: 'ai dm reply', channel_name: 'LongFast')
    )
  end

  it 'does not dispatch pwn-ai unless the channel is on ai_whitelist' do
    mesh_env[:ai_whitelist] = []
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    expect(dispatch(text: '@ai hello')).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'does not dispatch pwn-ai unless the message begins with @ai' do
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    expect(dispatch(text: 'hello on channel')).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'dispatches pwn-ai on an encrypted whitelisted shared channel when the text starts with @ai' do
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai says hi')
    allow(described_class).to receive(:mesh_send_text)
    allow(Thread).to receive(:new).and_yield
    described_class.send(
      :mesh_maybe_dispatch_to_pwn_ai,
      text: '@ai hello on channel',
      from: '!abcabcab',
      to: '!ffffffff',
      channel_name: 'LongFast'
    )
    expect(PWN::AI::Agent::Loop).to have_received(:run).with(
      hash_including(request: 'hello on channel', nested: true, engine: :ollama)
    )
    expect(described_class).to have_received(:mesh_send_text).with(hash_including(to: '!ffffffff', text: 'ai says hi'))
  end
end
