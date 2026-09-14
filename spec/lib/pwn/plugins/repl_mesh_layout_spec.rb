# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh terminal layout' do
  it 'keeps a 5-row header and 5-row compose on a 24-line terminal' do
    layout = described_class.send(:mesh_layout, lines: 24, cols: 80)
    expect(layout[:header]).to eq(5)
    expect(layout[:tx]).to eq(5)
    expect(layout[:body]).to eq(14)
    expect(layout[:tx_top]).to eq(19)
  end

  it 'shrinks conversation so header, conversation and compose fit a 12-line terminal' do
    layout = described_class.send(:mesh_layout, lines: 12, cols: 40)
    expect(layout[:header] + layout[:body] + layout[:tx]).to eq(12)
    expect(layout[:tx_top] + layout[:tx]).to eq(12)
    expect(layout[:header]).to be >= 3
    expect(layout[:tx]).to be >= 3
    expect(layout[:body]).to be >= 3
  end

  it 'keeps compose on-screen on a 10-line terminal by shrinking conversation first' do
    layout = described_class.send(:mesh_layout, lines: 10, cols: 40)
    expect(layout[:header] + layout[:body] + layout[:tx]).to eq(10)
    expect(layout[:tx_top]).to be < 10
    expect(layout[:tx_top] + layout[:tx]).to eq(10)
  end
end
