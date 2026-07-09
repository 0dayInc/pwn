# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::AdalmPluto do
  it 'should display information for authors' do
    expect(PWN::FFI::AdalmPluto).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::AdalmPluto).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::AdalmPluto).to respond_to :available?
  end

  it 'should report library info when libiio is present' do
    skip 'libiio not installed' unless PWN::FFI::AdalmPluto.available?

    info = PWN::FFI::AdalmPluto.info
    expect(info[:available]).to eq(true)
    expect(info[:major]).to be_a(Integer)
    expect(info[:minor]).to be_a(Integer)
  end

  it 'should list URIs (possibly empty) when libiio is present' do
    skip 'libiio not installed' unless PWN::FFI::AdalmPluto.available?

    list = PWN::FFI::AdalmPluto.list_uris
    expect(list).to be_a(Array)
  end

  it 'should appear in PWN::FFI.backends' do
    expect(PWN::FFI.backends).to have_key(:AdalmPluto)
  end
end
