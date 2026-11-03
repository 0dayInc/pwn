# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::PreflightChecker, 'native YubiKey facade contract' do
  it 'routes per-application host-only probes through the real facade without opening or enumerating a device' do
    device = PWN::Plugins::YubiKey
    transport = device::Transport
    allow(transport).to receive(:available?).with({ application: :fido }).and_return(true)
    allow(transport).to receive(:available?).with({ application: :oath }).and_return(true)
    expect(transport).not_to receive(:devices)
    expect(transport).not_to receive(:open)
    %i[devices info command challenge_response oath_code].each { |method| expect(device).not_to receive(method) }
    row = described_class.check(names: ['PWN::Plugins::YubiKey']).first
    expect(row).to include(status: :ok, missing_bins: [], missing_native: [])
    expect(transport).to have_received(:available?).with({ application: :fido }).once
    expect(transport).to have_received(:available?).with({ application: :oath }).once
  end
end
