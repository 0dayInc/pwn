# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh node ID formatting' do
  it 'preserves broadcast and non-node labels while formatting valid node values' do
    { 0 => '!00000000', 0xffffffff => '!ffffffff', '!ABCDEF1' => '!0abcdef1',
      '!ffffffff' => '!ffffffff', 'LongFast' => 'LongFast', '!nothex' => '!nothex' }.each do |id, expected|
      expect(described_class.send(:mesh_format_node_id, id: id)).to eq(expected)
    end
  end

  it 'pads the local numeric node ID to eight hex digits' do
    expect(described_class.send(:mesh_self_node_id, obj: { my_node_num: 0xabcdef1 })).to eq('!0abcdef1')
    expect(described_class.send(:mesh_self_node_id, obj: { my_node_num: 0xb0b })).to eq('!00000b0b')
  end

  it 'pads transport-enriched IDs before painting and remembering a DM sender' do
    stub_const('PWN::MeshObj', { my_node_num: 0xb0b })
    stub_const('PWN::MeshLastDm', nil)
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshRxState', {})
    stub_const('PWN::MeshMutex', Mutex.new)
    win = double('conversation', maxx: 80, attron: nil, attroff: nil, addstr: nil, refresh: nil)
    stub_const('PWN::MeshRxBodyWin', win)
    allow(Curses).to receive(:color_pair).and_return(0)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    allow(described_class).to receive(:mesh_env_hash).and_return({ transport: 'mqtt', channel: {} })
    described_class.send(:mesh_handle_rx, msg: { packet: {
                           node_id_from: '!abcdef1', node_id_to: '!b0b',
                           decoded: { portnum: 1, payload: 'hello' }
                         } })
    expect(win).to have_received(:addstr).with(a_string_including('!0abcdef1', '!00000b0b (ME)'))
    expect(PWN::MeshLastDm).to eq('!0abcdef1')
  end
end
