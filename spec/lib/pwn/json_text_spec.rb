# frozen_string_literal: true

require 'spec_helper'

describe PWN::JSONText do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  %w[ISO-8859-1 UTF-16LE UTF-16BE].each do |encoding|
    it "preserves characters in #{encoding} text through every JSON entry point" do
      text = 'café'.encode(encoding).freeze
      value = { text => [text] }
      [JSON.generate(value), JSON.fast_generate(value), JSON.pretty_generate(value), JSON.dump(value), value.to_json].each do |wire|
        expect(JSON.parse(wire)).to eq('café' => ['café'])
      end
      expect(described_class.prepare(value: text)).to eq('café')
      expect(text.encoding.name).to eq(encoding)
      expect(text).to eq('café'.encode(encoding))
    end
  end

  it 'rejects cycles and excessive container depth before unbounded JSON encoders run' do
    cycle = []
    cycle << cycle
    expect { described_class.prepare(value: cycle) }.to raise_error(JSON::NestingError)
    expect { JSON.dump(cycle) }.to raise_error(JSON::NestingError)
    expect { JSON.generate(cycle, max_nesting: false) }.to raise_error(JSON::NestingError)
    deep = Array.new(101) { [] }.inject('leaf') { |value, array| array << value }
    expect { described_class.prepare(value: deep) }.to raise_error(JSON::NestingError)
    branch = ['shared']
    expect(JSON.parse(JSON.dump([branch, branch]))).to eq([['shared'], ['shared']])
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
