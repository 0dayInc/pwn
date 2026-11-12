# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::BusPirate do
  it 'preserves a serial acquisition failure instead of masking it with an undefined local' do
    allow(PWN::Plugins::Serial).to receive(:connect).and_raise(IOError, 'fixture acquisition failed')
    expect { described_class.connect(block_dev: '/fixture/missing') }.to raise_error(IOError, 'fixture acquisition failed')
  end

  it 'rejects an unavailable explicit screen device without opening the default device' do
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with('/fixture/missing').and_return(false)
    allow(File).to receive(:exist?).with('/usr/bin/screen').and_return(true)
    allow(described_class).to receive(:system)
    expect { described_class.connect_via_screen(block_dev: '/fixture/missing') }.to raise_error(ArgumentError, /block device/)
    expect(described_class).not_to have_received(:system)
  end
end
