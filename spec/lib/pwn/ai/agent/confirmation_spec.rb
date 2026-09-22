# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'yaml'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::Confirmation do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'pauses an exploit-tier call with a concise diff and caches ACK per engagement' do
    Dir.mktmpdir('pwn-ack-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      scope = File.join(dir, '.pwn', 'scope.yaml')
      FileUtils.mkdir_p(File.dirname(scope))
      File.write(scope, YAML.dump(
                          'enabled' => false,
                          'confirmation' => {
                            'read_only' => 'auto',
                            'active_scan' => 'auto',
                            'exploit' => 'prompt',
                            'destructive' => 'prompt'
                          }
                        ))
      first = described_class.gate(
        name: 'exploitdev',
        args: { action: 'ret2libc', path: '/tmp/bin' },
        engagement_id: 'lab',
        scope_path: scope
      )
      expect(first[:needs_ack]).to eq(true)
      expect(first[:diff].to_s).to include('exploitdev')
      expect(first[:diff].to_s).to include('ret2libc')
      expect(described_class.gate(name: 'nmap_scan', args: { since: 'yesterday' }, engagement_id: 'lab', scope_path: scope)).to be_nil
      second = described_class.gate(
        name: 'exploitdev',
        args: { action: 'ret2libc', path: '/tmp/bin' },
        engagement_id: 'lab',
        operator_ack: true,
        scope_path: scope
      )
      expect(second).to be_nil
      third = described_class.gate(
        name: 'exploitdev',
        args: { action: 'pattern_create', n: 64 },
        engagement_id: 'lab',
        scope_path: scope
      )
      expect(third).to be_nil
    end
  end

  it 'denies exploit on an unattended mission when scope confirmation is absent' do
    Dir.mktmpdir('pwn-ack-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      denied = described_class.gate(name: 'exploitdev', args: { action: 'ret2libc' }, unattended: true, scope_path: File.join(dir, 'missing.yaml'))
      expect(denied[:code]).to eq('ACK_DENY')
    end
  end

  it 'does not reuse an ACK when the tool arguments change under ack_scope' do
    Dir.mktmpdir('pwn-ack-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      scope = File.join(dir, '.pwn', 'scope.yaml')
      FileUtils.mkdir_p(File.dirname(scope))
      File.write(scope, YAML.dump('confirmation' => { 'exploit' => 'prompt' }))
      described_class.gate(name: 'exploitdev', args: { action: 'ret2libc', host: '10.0.0.5' }, engagement_id: 'lab', operator_ack: true, ack_scope: true, scope_path: scope)
      again = described_class.gate(name: 'exploitdev', args: { action: 'pattern_create', host: '10.0.0.5' }, engagement_id: 'lab', ack_scope: true, scope_path: scope)
      expect(again[:needs_ack]).to eq(true)
    end
  end
end
