# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'yaml'
require 'tmpdir'
require 'fileutils'

describe 'PWN::AI::Agent::Dispatch confirmation tiers' do
  it 'does not execute an exploit-tier tool until the engagement ACK is cached' do
    Dir.mktmpdir('pwn-ack-dispatch-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      ran = false
      PWN::AI::Agent::Registry.discover(force: true)
      PWN::AI::Agent::Registry.register(
        name: 'spec_exploit_tier',
        toolset: 'pwn',
        schema: {
          name: 'spec_exploit_tier',
          description: 'fixture exploit-tier tool',
          parameters: { type: 'object', properties: { action: { type: 'string' } }, required: %w[action] }
        },
        handler: lambda { |_args|
          ran = true
          { ran: true }
        }
      )
      scope = File.join(dir, '.pwn', 'scope.yaml')
      FileUtils.mkdir_p(File.dirname(scope))
      File.write(scope, YAML.dump('enabled' => false, 'confirmation' => { 'exploit' => 'prompt', 'destructive' => 'prompt', 'read_only' => 'auto', 'active_scan' => 'auto' }))
      raw = PWN::AI::Agent::Dispatch.call(
        tool_call: { function: { name: 'spec_exploit_tier', arguments: JSON.generate(action: 'ret2libc') } },
        engagement_id: 'lab',
        scope_path: scope
      )
      row = JSON.parse(raw, symbolize_names: true)
      expect(ran).to eq(false)
      expect(row[:needs_ack]).to eq(true)
      expect(row[:diff].to_s).to include('spec_exploit_tier')
      acked = PWN::AI::Agent::Dispatch.call(
        tool_call: { function: { name: 'spec_exploit_tier', arguments: JSON.generate(action: 'ret2libc') } },
        engagement_id: 'lab',
        operator_ack: true,
        scope_path: scope
      )
      expect(JSON.parse(acked, symbolize_names: true)[:success]).to eq(true)
      expect(ran).to eq(true)
    ensure
      PWN::AI::Agent::Registry.instance_variable_get(:@entries).delete('spec_exploit_tier')
    end
  end
end
