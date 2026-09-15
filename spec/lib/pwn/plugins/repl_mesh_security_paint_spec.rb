# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh message security indicators' do
  [true, false].each do |local|
    [
      ['private channel', 'cHdu', false, '🔒'],
      ['public channel', 'AQ==', false, '🔍'],
      ['expanded public key', '1PG7OiApB1nwvP+rz05pAQ==', false, '🔍'],
      ['unknown encryption', '', false, '🔍'],
      ['PKI packet', 'AQ==', true, '🔒']
    ].each do |label, psk, pki, icon|
      it "paints #{icon} for #{local ? 'sent' : 'received'} #{label}" do
        env = { transport: 'mqtt', channel: { active: 'LongFast', LongFast: { psk: psk } } }
        allow(described_class).to receive(:mesh_env_hash).and_return(env)
        allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
        stub_const('PWN::MeshLastTx', nil)
        stub_const('PWN::MeshLastChannel', nil)
        stub_const('PWN::MeshMutex', Mutex.new)
        stub_const('PWN::MeshRxState', {})
        win = double('conversation', maxx: 80, attron: nil, attroff: nil, addstr: nil, refresh: nil)
        stub_const('PWN::MeshRxBodyWin', win)
        allow(Curses).to receive(:color_pair).and_return(0)
        described_class.send(
          :mesh_handle_rx,
          local: local, channel_name: 'LongFast',
          msg: { packet: { node_id_from: '!aabbccdd', node_id_to: '!ffffffff', pki_encrypted: pki,
                           decoded: { portnum: 1, payload: 'security test' } } }
        )
        expect(win).to have_received(:addstr).with(a_string_including(icon, '!aabbccdd', 'LongFast'))
        expect(Curses).to have_received(:color_pair).with(local ? 23 : 21).twice
      end
    end
  end
end
