# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::SoapySDR do
  it 'should display information for authors' do
    expect(PWN::FFI::SoapySDR).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::SoapySDR).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::SoapySDR).to respond_to :available?
  end

  it 'should report API info when libSoapySDR is present' do
    skip 'libSoapySDR not installed' unless PWN::FFI::SoapySDR.available?

    info = PWN::FFI::SoapySDR.info
    expect(info[:available]).to eq(true)
    expect(info[:api]).to match(/\d+\.\d+/)
  end
end
