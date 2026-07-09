# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::HackRF do
  it 'should display information for authors' do
    expect(PWN::FFI::HackRF).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::HackRF).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::HackRF).to respond_to :available?
  end

  it 'should report library info when libhackrf is present' do
    skip 'libhackrf not installed' unless PWN::FFI::HackRF.available?

    info = PWN::FFI::HackRF.info
    expect(info[:available]).to eq(true)
    expect(info[:library_version]).to be_a(String)
  end
end
