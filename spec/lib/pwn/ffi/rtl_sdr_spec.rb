# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::RTLSdr do
  it 'should display information for authors' do
    expect(PWN::FFI::RTLSdr).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::RTLSdr).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::RTLSdr).to respond_to :available?
  end

  it 'should list devices (possibly empty) when librtlsdr is present' do
    skip 'librtlsdr not installed' unless PWN::FFI::RTLSdr.available?

    list = PWN::FFI::RTLSdr.list_devices
    expect(list).to be_a(Array)
  end
end
