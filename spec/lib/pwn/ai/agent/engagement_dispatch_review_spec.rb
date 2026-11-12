# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Engagement, 'reviewed dispatch scope' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(@tmp, 'engagements', 'active'))
    @calls = []
    @registry_entries = PWN::AI::Agent::Registry.instance_variable_get(:@entries).dup
    PWN::AI::Agent::Registry.register(
      name: 'fixture_scope', toolset: 'fixture',
      schema: { name: 'fixture_scope', parameters: { type: 'object', properties: {} } },
      handler: lambda { |args|
        @calls << args
        { observation: 'offline fixture' }
      }
    )
  end

  after do
    PWN::AI::Agent::Registry.instance_variable_set(:@entries, @registry_entries)
  end

  def dispatch(args)
    JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { id: 'scope-fixture', function: { name: 'fixture_scope', arguments: JSON.generate(args) } }))
  end

  [
    { host: '2001:db8:2::42' },
    { url: 'https://[2001:db8:2::42]:8443/path' },
    { command: 'probe [2001:db8:2::42]:443' },
    { code: "probe(host: '2001:db8:2::42')" },
    { targets: [{ ip: '2001:db8:2::42' }] }
  ].each do |args|
    it "blocks the out-of-scope IPv6 target before executing #{args.keys.first}" do
      described_class.open(name: 'v6', scope_cidrs: ['2001:db8:1::/48'])
      expect(dispatch(args)).to include('success' => false, 'code' => 'SCOPE_DENY')
      expect(@calls).to be_empty
    end
  end

  [['192.0.2.0/24', '192.0.2.12', '198.51.100.12'], ['2001:db8:2::/48', '2001:db8:2::42', '2001:db8:1::42']].each do |cidr, denied, allowed|
    it "honors CIDR denies through Dispatch for #{cidr}" do
      FileUtils.mkdir_p(File.join(@tmp, '.pwn'))
      File.write(File.join(@tmp, '.pwn', 'roe.yaml'), YAML.dump('targets_deny' => [cidr]))
      expect(dispatch(host: denied)).to include('success' => false)
      expect(@calls).to be_empty
      expect(dispatch(host: allowed)).to include('success' => true)
    end
  end

  it 'preserves literal accepted names in the active pointer' do
    described_class.open(name: 'lab', scope_domains: ['first.example'])
    row = described_class.open(name: ' lab ', scope_domains: ['second.example'])
    expect(described_class.current_name).to eq(row[:name])
    expect(dispatch(host: 'first.example')).to include('success' => false)
    expect(dispatch(host: 'second.example')).to include('success' => true)
  end

  it 'rejects explicit empty selectors instead of opting out of the active scope' do
    described_class.open(name: 'lab', scope_domains: ['allowed.example'])
    expect { described_class.in_scope?(name: '', host: 'outside.example') }.to raise_error(ArgumentError, /engagement name/)
    expect { described_class.status(engagement: '') }.to raise_error(ArgumentError, /engagement name/)
    expect(described_class.in_scope?(host: 'outside.example')).to be(false)
  end

  it 'resolves the engagement alias to the same document through the root wrapper' do
    described_class.open(name: 'first', scope_domains: ['first.example'])
    described_class.open(name: 'second', scope_domains: ['second.example'])
    expect(PWN::Engagement.status(engagement: 'first')).to include(name: 'first', scope_domains: ['first.example'])
  end

  it 'allows in-scope IPv6 URLs without interpreting the path as a separate host' do
    described_class.open(name: 'v6', scope_cidrs: ['2001:db8:1::/48'])
    expect(dispatch(url: 'https://[2001:db8:1::42]/notes.txt')).to include('success' => true)
    expect(@calls.length).to eq(1)
  end
end
