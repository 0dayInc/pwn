# frozen_string_literal: true

require 'spec_helper'
require 'json'

# ─────────────────────────────────────────────────────────────────────────────
#  #1 — the LLM ↔ host contract.
#
#  A broken schema/handler silently degrades EVERY agent turn (the model
#  sees a tool that dispatch can't route, or JSON-Schema the engine
#  rejects). One table-driven spec over Registry.all catches the whole
#  class. NON-BLOCKING: pure in-process introspection over already-loaded
#  constants; no handler is invoked.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::AI::Agent::Registry — LLM↔host contract', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  let(:registry) { PWN::AI::Agent::Registry }
  let(:entries)  { registry.discover(force: true) && registry.all }

  it 'discovers at least the CORE_TOOLS and no two tools share a name' do
    names = entries.map(&:name)
    expect(names).not_to be_empty
    registry::CORE_TOOLS.each { |t| expect(names).to include(t), "CORE tool #{t} not registered" }
    expect(names.uniq.length).to eq(names.length), "duplicate tool names: #{names.tally.select { |_, c| c > 1 }.keys}"
  end

  it 'every entry has a well-formed schema (name matches, params object, required ⊆ properties)' do
    entries.each do |e|
      s = e.schema
      expect(s).to be_a(Hash), "#{e.name}: schema is not a Hash"
      expect(s[:name]).to eq(e.name), "#{e.name}: schema[:name] mismatch"
      expect(s[:description].to_s).not_to be_empty, "#{e.name}: empty description"
      params = s[:parameters]
      expect(params).to be_a(Hash), "#{e.name}: schema[:parameters] is not a Hash"
      expect(params[:type]).to eq('object'), "#{e.name}: parameters.type != 'object'"
      props = params[:properties] || {}
      expect(props).to be_a(Hash), "#{e.name}: parameters.properties is not a Hash"
      Array(params[:required]).each do |req|
        expect(props.keys.map(&:to_s)).to include(req.to_s),
                                          "#{e.name}: required '#{req}' not in properties #{props.keys}"
      end
    end
  end

  it 'every handler is callable with arity 1 (or -1) and every check is callable' do
    entries.each do |e|
      expect(e.handler).to respond_to(:call), "#{e.name}: handler not callable"
      expect([-1, 1]).to include(e.handler.arity), "#{e.name}: handler arity #{e.handler.arity}"
      expect(e.check).to respond_to(:call), "#{e.name}: check not callable"
      expect(e.max_chars).to be_a(Integer).and(be_positive), "#{e.name}: bad max_chars"
    end
  end

  it '.toolsets covers every entry.toolset and .definitions round-trips JSON' do
    sets = registry.toolsets
    expect(sets).to be_an(Array).and match_array(entries.map(&:toolset).uniq.sort)
    defs = registry.definitions
    expect(defs).to be_an(Array).and all(include(type: 'function'))
    round = JSON.parse(JSON.generate(defs))
    expect(round.length).to eq(defs.length)
    round.each { |d| expect(d['function']).to include('name', 'parameters') }
  end

  it 'agent_spawn schema toolset enum ⊆ Registry.toolsets (personas can only be granted real toolsets)' do
    spawn = registry.lookup(name: 'agent_spawn')
    skip 'agent_spawn not registered' unless spawn
    enum = spawn.schema.dig(:parameters, :properties, :toolsets, :items, :enum)
    if enum
      expect(enum - registry.toolsets).to be_empty,
                                          "agent_spawn advertises unknown toolsets: #{enum - registry.toolsets}"
    end
  end

  describe '.rank (C1 keyword+bandit router)' do
    it 'returns [] for a nonsense query' do
      expect(registry.rank(query: 'zzyzx qxqxqx').map(&:name)).to be_empty
    end

    it 'ranks shell for a shell-shaped request' do
      names = registry.rank(query: 'run a shell command on the host').map(&:name)
      expect(names).to include('shell')
    end

    it 'ranks memory_remember for a remember-shaped request' do
      names = registry.rank(query: 'remember a fact for later').map(&:name)
      expect(names).to include('memory_remember')
    end
  end
end
