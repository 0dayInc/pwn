# frozen_string_literal: true

require 'spec_helper'

describe PWN::Driver do
  it 'should display information for authors' do
    authors_response = PWN::Driver
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Driver
    expect(help_response).to respond_to :help
  end

  it 'uses its own parser help when no driver-specific options were supplied' do
    parser = PWN::Driver::Parser.new
    parser.opts = { pwn_env_path: nil, pwn_dec_path: nil }
    stub_const('ARGV', [])
    allow(PWN::Config).to receive(:refresh_env)
    allow(parser).to receive(:`).and_return('external help must not be used')
    expect(parser.banner).to eq("USAGE: #{File.basename($PROGRAM_NAME)} [opts]\n")
    expect do
      expect { parser.parse! }.to raise_error(SystemExit) { |error| expect(error.status).to eq(1) }
    end.to output(parser.to_s).to_stdout
    expect(parser).not_to have_received(:`)
  end
end
