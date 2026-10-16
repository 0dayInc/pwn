# frozen_string_literal: true

require 'spec_helper'

describe PWN::JSONText do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'retags binary UTF-8 and scrubs malformed bytes before JSON encode' do
    binary = "status \u2022 ok".b
    malformed = "\xff\xfe".b
    prev = $stderr
    $stderr = StringIO.new
    generated = JSON.generate(stdout: binary)
    dumped = JSON.dump(stdout: binary.dup)
    wired = { stdout: binary.dup }.to_json
    scrubbed = JSON.generate(stdout: malformed)
    err = $stderr.string
    expect(err).not_to include('UTF-8 string passed as BINARY')
    expect(generated).to include('status')
    expect(dumped).to include('status')
    expect(wired).to include('status')
    expect { JSON.parse(scrubbed) }.not_to raise_error
    expect(described_class.prepare(value: binary)).to eq("status \u2022 ok")
  ensure
    $stderr = prev
  end
end
