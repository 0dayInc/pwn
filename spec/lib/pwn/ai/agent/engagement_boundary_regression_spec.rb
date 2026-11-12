# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Engagement, 'persistence boundaries' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(described_class::ROOT, 'active'))
  end

  it 'rejects escaping names before writing either the document or pointer' do
    expect { described_class.open(name: '../outside') }.to raise_error(ArgumentError, /engagement name/i)
    expect(File).not_to exist(File.join(@tmp, 'outside.json'))
    expect(File).not_to exist(described_class::ACTIVE_FILE)
  end

  it 'rejects escaping explicit and persisted names before reading a document' do
    FileUtils.mkdir_p(described_class::ROOT)
    File.write(File.join(@tmp, 'outside.json'), '{"scope_domains": ["outside.example"]}')
    expect { described_class.status(name: '../outside') }.to raise_error(ArgumentError, /engagement name/i)
    File.write(described_class::ACTIVE_FILE, '../outside')
    expect { described_class.status }.to raise_error(ArgumentError, /engagement name/i)
  end

  it 'validates a name without changing its spelling' do
    expect(described_class.validate_name(name: 'Lab_2026.v1')).to eq('Lab_2026.v1')
    ['.', '..', '/absolute', 'nested/name', 'nested\\name', "bad\0name", ''].each do |name|
      expect { described_class.validate_name(name: name) }.to raise_error(ArgumentError, /engagement name/i)
    end
  end

  it 'reserves the active pointer and metadata suffix before creating an engagement' do
    ['active', 'existing.json'].each do |name|
      expect { described_class.open(name: name) }.to raise_error(ArgumentError, /engagement name/i)
    end
    expect(File).not_to exist(described_class::ACTIVE_FILE)
    expect(File).not_to exist(described_class::ROOT)
  end
end
