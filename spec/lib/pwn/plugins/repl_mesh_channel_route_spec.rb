# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

RSpec.shared_context 'mesh packet channel fixture' do
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
end

describe PWN::Plugins::REPL, 'mesh packet channel routing' do
  include_context 'mesh packet channel fixture'

  [false, true].each do |local|
    it "paints absolute source and destination paths for #{local ? 'TX' : 'RX'}" do
      mesh_env[:mqtt] = { region: 'US/CA' }
      win = double('rx', maxx: 200)
      %i[attron attroff addstr refresh].each { |method| allow(win).to receive(method) }
      allow(Curses).to receive(:color_pair) { |color| color }
      PWN.const_set(:MeshRxBodyWin, win)
      PWN.const_set(:MeshMutex, Mutex.new)
      allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
      described_class.send(:mesh_handle_rx, local: local, msg: { packet: {
                             channel: 1, from: 0xb0b, to: 0xffffffff,
                             decoded: { portnum: 1, payload: 'Absolute paths' }
                           } })
      expect(win).to have_received(:addstr).with(a_string_including('US/CA/2/e/LongFast/!00000b0b (ME)', 'US/CA/2/e/LongFast/#'))
      expect(win).to have_received(:attron).with((local ? 23 : 21) | Curses::A_BOLD)
    end
    it "includes the original sender and message in a #{local ? 'sent' : 'received'} reaction without changing header colors" do
      win = double('rx', maxx: 200)
      %i[attron attroff addstr refresh].each { |method| allow(win).to receive(method) }
      allow(Curses).to receive(:color_pair) { |color| color }
      PWN.const_set(:MeshRxBodyWin, win)
      PWN.const_set(:MeshMutex, Mutex.new)
      PWN.const_set(:MeshRxState, {})
      allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
      original = Meshtastic::MeshPacket.new(id: 123, from: 0xaabbccdd, to: 0xffffffff, channel: 1,
                                            decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'Meet at noon' }).to_h
      described_class.send(:mesh_handle_rx, msg: { packet: original })
      reaction = Meshtastic::MeshPacket.new(id: 124, from: 0xb0b, to: 0xffffffff, channel: 1,
                                            decoded: { portnum: :TEXT_MESSAGE_APP, payload: '👍'.b, emoji: 1, reply_id: 123 }).to_h
      described_class.send(:mesh_handle_rx, local: local, msg: { packet: reaction })
      expect(win).to have_received(:addstr).with(" Reacted to: \"!aabbccdd >> Meet at noon\" with: 👍.\n")
      expect(win).to have_received(:attron).with((local ? 23 : 21) | Curses::A_BOLD).at_least(:once)
      expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once
      reply = Meshtastic::MeshPacket.new(id: 125, from: 0xb0b, to: 0xffffffff, channel: 1,
                                         decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'See you there!', reply_id: 123 }).to_h
      described_class.send(:mesh_handle_rx, local: local, msg: { packet: reply })
      expect(win).to have_received(:addstr).with(" Replied to: \"!aabbccdd >> Meet at noon\" with: See you there!\n")
    end
  end

  it 'uses the received topic region for both endpoints of a DM' do
    mesh_env[:mqtt] = { region: 'US' }
    win = double('rx', maxx: 200)
    %i[attron attroff addstr refresh].each { |method| allow(win).to receive(method) }
    allow(Curses).to receive(:color_pair).and_return(0)
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    described_class.send(:mesh_handle_rx, msg: {
                           topic: 'msh/US/CA/2/e/LongFast/!aabbccdd',
                           packet: { channel: 1, from: 0xaabbccdd, to: 0xb0b, decoded: { portnum: 1, payload: 'DM' } }
                         })
    expect(win).to have_received(:addstr).with(a_string_including('US/CA/2/e/LongFast/!aabbccdd', 'US/CA/2/e/LongFast/!00000b0b (ME)'))
  end

  it 'preserves a configured channel topic without a wildcard suffix' do
    mesh_env[:channel][:LongFast][:topic] = '2/e/LongFast'
    expect(described_class.send(:mesh_conversation_path, env: mesh_env, channel_name: 'LongFast')).to eq('US/2/e/LongFast')
  end

  it 'remembers the actual transmitted packet ID for reactions to locally sent messages' do
    sent = nil
    allow(Meshtastic::Serial).to receive(:send_to_radio) do |args|
      sent = Meshtastic::ToRadio.decode(args[:to_radio]).packet
    end
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    described_class.send(:mesh_send_text, env: mesh_env, obj: radio, text: 'Local message', channel_name: 'LongFast')
    expect(sent.decoded.payload).to eq('Local message')
    packet = { decoded: { emoji: 1, reply_id: sent.id } }
    text = described_class.send(:mesh_reaction_text, packet: packet, text: '👍', channel: 'LongFast', index: 1)
    expect(text).to eq('Reacted to: "!00000b0b >> Local message" with: 👍.')
  end

  it 'recovers a reaction target from transport history when the display cache is empty' do
    radio[:proto_data] << Meshtastic::FromRadio.new(packet: {
                                                      id: 123, from: 0xaabbccdd, to: 0xffffffff, channel: 1,
                                                      decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'Earlier message' }
                                                    }).to_h
    packet = { channel: 1, decoded: { emoji: 1, reply_id: 123 } }
    text = described_class.send(:mesh_reaction_text, packet: packet, text: '👍', channel: 'LongFast', index: 1)
    expect(text).to eq('Reacted to: "!aabbccdd >> Earlier message" with: 👍.')
  end

  it 'resolves the same radio slot after its channel name becomes known' do
    described_class.send(:mesh_reaction_text, packet: { id: 123, decoded: {} }, text: 'Before channel listing', from: '!aabbccdd', channel: '', index: 1)
    packet = { decoded: { emoji: 1, reply_id: 123 } }
    text = described_class.send(:mesh_reaction_text, packet: packet, text: '👍', channel: 'LongFast', index: 1)
    expect(text).to eq('Reacted to: "!aabbccdd >> Before channel listing" with: 👍.')
    other = described_class.send(:mesh_reaction_text, packet: packet, text: '👍', channel: 'LongFast', index: 2)
    expect(other).to include('original message unavailable')
  end

  it 'labels unavailable reaction targets rather than inventing their sender or text' do
    packet = { decoded: { emoji: 1, reply_id: 999 } }
    text = described_class.send(:mesh_reaction_text, packet: packet, text: '👍', channel: 'LongFast', index: 1)
    expect(text).to eq('Reacted to: "original message unavailable (packet 999)" with: 👍.')
    packet[:decoded][:emoji] = 0
    expect(described_class.send(:mesh_reaction_text, packet: packet, text: 'Reply')).to eq('Replied to: "original message unavailable (packet 999)" with: Reply')
    packet[:decoded].delete(:reply_id)
    expect(described_class.send(:mesh_reaction_text, packet: packet, text: '👍')).to eq('👍')
  end

  it 'does not route LongFast to disabled protobuf slots with omitted roles' do
    mesh_env[:channel][:LongFast].delete(:radio_index)
    radio[:proto_data] = [
      Meshtastic::FromRadio.new(channel: Meshtastic::Channel.new(index: 1, role: :SECONDARY, settings: { name: 'LongFast' })).to_h,
      Meshtastic::FromRadio.new(channel: Meshtastic::Channel.new(index: 7, role: :DISABLED)).to_h
    ]
    expect(described_class.send(:mesh_radio_index_for_name, env: mesh_env, obj: radio, name: 'LongFast')).to eq(1)
    expect(described_class.send(:mesh_device_channel_meta, obj: radio).keys).to eq([1])
    radio[:proto_data] << Meshtastic::FromRadio.new(channel: Meshtastic::Channel.new(index: 1, role: :DISABLED)).to_h
    expect(described_class.send(:mesh_device_channel_meta, obj: radio)).to be_empty
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
