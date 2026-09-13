# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh packet channel routing' do
  let(:mesh_env) do
    {
      transport: 'serial',
      dispatch_to_pwn_ai: true,
      channel: {
        active: 'LongFast',
        LongFast: { psk: 'cHdu', radio_index: 1 }
      }
    }
  end

  let(:radio) do
    {
      my_node_num: 0xb0b,
      proto_data: [
        { channel: { index: 0, settings: { name: '' }, role: :PRIMARY } },
        { channel: { index: 1, settings: { name: 'LongFast' }, role: :SECONDARY } }
      ]
    }
  end

  before do
    PWN::Env[:plugins] ||= {}
    @prev_mesh = PWN::Env[:plugins][:meshtastic]
    PWN::Env[:plugins][:meshtastic] = mesh_env
    %i[MeshDispatchLock MeshObj MeshTransport MeshLastDm MeshRxBodyWin MeshMutex MeshRxState].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
    PWN.const_set(:MeshTransport, :serial)
    PWN.const_set(:MeshObj, radio)
  end

  after do
    PWN::Env[:plugins][:meshtastic] = @prev_mesh if PWN::Env[:plugins].is_a?(Hash)
    %i[MeshDispatchLock MeshObj MeshTransport MeshLastDm MeshRxBodyWin MeshMutex MeshRxState].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
  end

  it 'paints and replies on the packet radio slot instead of the selected channel' do
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai on one')
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          channel: 1,
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: 'hello from one' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_matching(/LongFast/)).at_least(:once)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'treats an omitted protobuf channel as radio slot zero' do
    mesh_env[:channel][:LongFast][:radio_index] = 0
    radio[:proto_data] = [
      { channel: { index: 0, settings: { name: 'LongFast' }, role: :PRIMARY } }
    ]
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: 'hello' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_including('LongFast')).at_least(:once)
  end

  it 'paints the env channel name when slot zero firmware name is blank' do
    mesh_env[:channel].delete(:LongFast)
    mesh_env[:channel][:LongFast] = { psk: 'cHdu' }
    radio[:proto_data] = [
      { channel: { index: 0, settings: { name: '', psk: 'pwn' }, role: :PRIMARY } }
    ]
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: 'hello' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_including('LongFast')).at_least(:once)
  end

  it 'dispatches pwn-ai on omitted slot zero when the env name is encrypted and whitelisted' do
    mesh_env[:dispatch_to_pwn_ai] = true
    mesh_env[:ai_whitelist] = ['LongFast']
    mesh_env[:channel].delete(:LongFast)
    mesh_env[:channel][:LongFast] = { psk: 'cHdu' }
    radio[:proto_data] = [
      { channel: { index: 0, settings: { name: '' }, role: :PRIMARY } }
    ]
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:active] = 'ollama'
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai on zero')
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: '@ai hello on zero' }
        }
      }
    )
    expect(PWN::AI::Agent::Loop).to have_received(:run).with(
      hash_including(request: 'hello on zero', nested: true, engine: :ollama)
    )
    expect(described_class).to have_received(:mesh_send_text).with(
      hash_including(to: '!ffffffff', text: 'ai on zero', channel_name: 'LongFast', radio: 0)
    )
  end

  it 'paints the first env channel name on unnamed radio slot zero' do
    mesh_env.delete(:ai_whitelist)
    mesh_env[:channel].delete(:LongFast)
    mesh_env[:channel][:LongFast] = { psk: 'cHdu' }
    radio[:proto_data] = [
      { channel: { settings: { name: '' }, role: :PRIMARY } }
    ]
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run)
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: '@ai hello first' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_including('LongFast')).at_least(:once)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'answers @ai on the first radio listing when AI REPLIES is on and the env name is whitelisted' do
    mesh_env[:dispatch_to_pwn_ai] = true
    mesh_env[:ai_whitelist] = ['LongFast']
    mesh_env[:channel].delete(:LongFast)
    mesh_env[:channel][:LongFast] = { psk: 'cHdu' }
    radio[:proto_data] = [
      { channel: { settings: { name: '' }, role: :PRIMARY } }
    ]
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:active] = 'ollama'
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai on first')
    allow(Thread).to receive(:new).and_yield
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: '@ai hello first' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_including('LongFast')).at_least(:once)
    expect(PWN::AI::Agent::Loop).to have_received(:run).with(
      hash_including(request: 'hello first', nested: true, engine: :ollama)
    )
    expect(described_class).to have_received(:mesh_send_text).with(
      hash_including(to: '!ffffffff', text: 'ai on first', channel_name: 'LongFast', radio: 0)
    )
  end
end
