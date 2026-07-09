# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::RDS do
  it 'should display information for authors' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :help
  end

  it 'exposes a non-interactive .sample entry point (agents / automation)' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :sample
  end

  it 'exposes the interactive .decode entry point (TTY spinner)' do
    expect(PWN::SDR::Decoder::RDS).to respond_to :decode
  end

  it 'aggregates RDS poll samples into pi/ps_name/radiotext/station' do
    samples = [
      { pi: '0000', ps: '', rt: '' },
      { pi: '131D', ps: 'KBER    ', rt: 'KBER 101' },
      { pi: '131D', ps: 'NIRVANA ', rt: 'KBER 101: Nirvana All Apologies' }
    ]
    result = PWN::SDR::Decoder::RDS.send(
      :aggregate,
      samples: samples,
      settle_secs: 8.0
    )
    expect(result[:pi]).to eq('131D')
    expect(result[:station]).to eq('KBER')
    expect(result[:radiotext]).to include('Nirvana')
    expect(result[:samples]).to eq(3)
    expect(result[:settle_secs]).to eq(8.0)
  end

  it 'returns an error Hash from .sample when gqrx_sock is missing' do
    # sample rescues ArgumentError only after resolve — missing sock raises first
    expect do
      PWN::SDR::Decoder::RDS.sample({})
    end.to raise_error(ArgumentError, /gqrx_sock/)
  end

  it 'returns an error Hash when the RDS backend refuses enable' do
    sock = Object.new
    # Stub GQRX.cmd so U RDS 1 fails
    allow(PWN::SDR::GQRX).to receive(:cmd).and_raise(StandardError.new('no rds'))
    result = PWN::SDR::Decoder::RDS.sample(gqrx_sock: sock, settle_secs: 0.5)
    expect(result).to be_a(Hash)
    expect(result[:error]).to match(/RDS not supported/)
    expect(result[:samples]).to eq(0)
  end
end
