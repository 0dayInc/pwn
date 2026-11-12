# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::MCP, 'backend-bound sessions' do
  before do
    described_class.reset!
    %w[AuditOne AuditTwo].each do |name|
      backend = Module.new
      backend.define_singleton_method(:connect) { |_opts| {} }
      backend.define_singleton_method(:disconnect) { |_opts| {} }
      backend.define_singleton_method(:list_tools) { |_opts| [] }
      backend.define_singleton_method(:call_tool) { |_opts| { parsed: 'fixture' } }
      stub_const("PWN::AI::MCP::#{name}", backend)
    end
    described_class.connect(backend: 'audit_one', session_id: 'shared-fixture')
  end

  after { described_class.reset! }

  %i[connect list_tools call_tool disconnect].each do |operation|
    it "rejects #{operation} for a session belonging to another explicit backend" do
      expect(PWN::AI::MCP::AuditOne).not_to receive(:call_tool)
      expect(PWN::AI::MCP::AuditOne).not_to receive(:list_tools)
      expect do
        described_class.public_send(operation, backend: 'audit_two', session_id: 'shared-fixture', name: 'echo')
      end.to raise_error(ArgumentError, /session.*audit_one.*audit_two/i)
      expect(described_class.invoke(action: 'status', session_id: 'shared-fixture')).to include(connected: true, backend: 'audit_one')
    end
  end

  it 'allows explicit force reconnect and leaves the new backend usable' do
    expect(described_class.connect(backend: 'audit_two', session_id: 'shared-fixture', force: true)).to include(backend: 'audit_two')
    expect(described_class.call_tool(session_id: 'shared-fixture', name: 'echo')).to include(backend: 'audit_two', parsed: 'fixture')
  end
end
