# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

describe PWN::Plugins::TTYSpinner do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'stop joins the auto_spin worker so no frames are written after the response' do
    io = StringIO.new
    spin = described_class.start(output: io, format: :dots)
    spin.auto_spin
    worker = spin.instance_variable_get(:@thread)
    expect(worker).to be_a(Thread)
    sleep 0.12
    described_class.stop(spin: spin)
    expect(worker.alive?).to eq false
    after_stop = io.string.dup
    sleep 0.2
    expect(io.string).to eq(after_stop)
    expect(spin.done?).to eq true
  end

  it 'stop is a no-op for nil and is idempotent' do
    expect { described_class.stop(spin: nil) }.not_to raise_error
    io = StringIO.new
    spin = described_class.start(output: io)
    described_class.stop(spin: spin)
    expect { described_class.stop(spin: spin) }.not_to raise_error
  end

  it 'stop shows the cursor on $stdout so the next PS1 is visible' do
    src = File.read(described_class.method(:stop).source_location.first)
    expect(src).to match(/Cursor\.show/)
    expect(src).to match(/\$stdout/)
  end

  it 'halt_all! stops every live worker even when stop was skipped' do
    expect(described_class).to respond_to :halt_all!
    io = StringIO.new
    spin = described_class.start(output: io, format: :dots)
    worker = spin.pwn_worker_thread
    expect(worker.alive?).to eq true
    described_class.halt_all!
    expect(worker.alive?).to eq false
    expect(spin.done?).to eq true
    after = io.string.dup
    sleep 0.2
    expect(io.string).to eq(after)
  end
end
