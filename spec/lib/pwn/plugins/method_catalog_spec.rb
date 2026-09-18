# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::Plugins::MethodCatalog do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'builds a JSON schema with side-effect class from YARD-style plugin docs' do
    row = described_class.schema(mod: 'PWN::Plugins::BasicAuth', method: 'encode')
    expect(row[:parameters][:properties].keys.map(&:to_s)).to include('username', 'password')
    expect(row[:side_effect].to_s).to match(/read_only|active_scan|exploit|destructive/)
    expect(row[:parameters][:additionalProperties]).to eq(false)
  end

  it 'rejects an unknown keyword arg pre-execution and echoes the schema' do
    out = described_class.guard_eval(code: "PWN::Plugins::BasicAuth.encode(not_a_key: 1, username: 'a')")
    expect(out[:error].to_s).to match(/unknown keyword/i)
    expect(out[:error].to_s).to include('not_a_key')
    expect(out[:schema]).to be_a(Hash)
    expect(out[:schema][:parameters] || out[:schema]['parameters']).not_to be_nil
  end
end
