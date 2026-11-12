# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::PS, 'cleanup header regression' do
  it 'does not turn a ps header or malformed PID into process group zero' do
    rows = [%w[USER %CPU PID PPID], ['fixture', '0.0', '42', '1'], ['fixture', '0.0', 'invalid', '1']]
    expect(Process).to receive(:kill).with('TERM', 42).once
    expect(Process).not_to receive(:kill).with('TERM', 0)
    described_class.cleanup_pids(pids_arr: rows)
  end
end
