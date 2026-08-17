# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::TTYSpinner do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  # StringIO is never a TTY so TTY::Spinner#write is a no-op, but the
  # auto_spin worker thread still starts. That is enough to prove #stop
  # actually joins the worker (the bug: ensure spin.stop left it sleeping
  # so a following response could still be overwritten).
  def run_rest_like(opts = {})
    provide_response = opts.fetch(:provide_response, true)
    spinner = true
    spin = described_class.start(output: StringIO.new) if spinner
    response = nil
    begin
      sleep 0.15
      response = provide_response ? 'HTTP_RESPONSE' : nil
      response
    ensure
      described_class.stop(spin: spin)
    end
  end

  it 'joins the auto_spin thread when a response is provided' do
    before = Thread.list.size
    result = run_rest_like(provide_response: true)
    expect(result).to eq('HTTP_RESPONSE')
    sleep 0.05
    expect(Thread.list.size).to eq(before)
  end

  it 'joins the auto_spin thread when no response is provided' do
    before = Thread.list.size
    result = run_rest_like(provide_response: false)
    expect(result).to be_nil
    sleep 0.05
    expect(Thread.list.size).to eq(before)
  end

  it 'is a no-op when spin is nil' do
    expect { described_class.stop(spin: nil) }.not_to raise_error
  end

  it 'marks the spinner done and dead after stop' do
    spin = described_class.start(output: StringIO.new)
    thread = spin.instance_variable_get(:@thread)
    expect(thread).not_to be_nil
    described_class.stop(spin: spin)
    expect(spin.done?).to be true
    expect(spin.spinning?).to be false
    expect(thread.status).to eq(false).or(be_nil)
  end
end
