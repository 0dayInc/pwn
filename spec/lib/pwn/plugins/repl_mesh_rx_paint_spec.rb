# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh incoming paint' do
  let(:mesh_env) do
    {
      transport: 'mqtt',
      channel: {
        active: 'LongFast',
        LongFast: { psk: 'AQ==', region: 'US/UT', topic: '2/e/#', channel_num: 8 }
      }
    }
  end

  before do
    PWN::Env[:plugins] ||= {}
    @prev_mesh = PWN::Env[:plugins][:meshtastic]
    PWN::Env[:plugins][:meshtastic] = mesh_env
  end

  after do
    PWN::Env[:plugins][:meshtastic] = @prev_mesh if PWN::Env[:plugins].is_a?(Hash)
  end

  it 'paints incoming RX in yellow with sender id and channel name or DM destination id' do
    win = double('rx', maxx: 80)
    allow(win).to receive(:attron)
    allow(win).to receive(:attroff)
    allow(win).to receive(:addstr)
    allow(win).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
    PWN.const_set(:MeshRxBodyWin, win)
    PWN.const_set(:MeshMutex, Mutex.new)
    PWN.const_set(:MeshRxState, {})
    described_class.send(
      :mesh_handle_rx,
      msg: {
        topic: 'msh/US/UT/2/e/LongFast/!abcabcab',
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!ffffffff',
          decoded: { portnum: 1, payload: 'hello on channel' }
        }
      }
    )
    expect(Curses).to have_received(:color_pair).with(21).at_least(:once)
    expect(win).to have_received(:addstr).with(a_string_matching(/!abcabcab/)).at_least(:once)
    expect(win).not_to have_received(:addstr).with(a_string_matching(/!abcabcab \(ME\)/))
    expect(win).to have_received(:addstr).with(a_string_matching(/LongFast/)).at_least(:once)
    expect(win).not_to have_received(:addstr).with(a_string_matching(/\bDM\b/))
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!00000b0b',
          decoded: { portnum: 1, payload: 'hello in dm' }
        }
      }
    )
    expect(win).to have_received(:addstr).with(a_string_matching(/!00000b0b \(ME\)/)).at_least(:once)
  ensure
    %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
  end
end
