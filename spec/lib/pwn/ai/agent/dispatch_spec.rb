# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::Agent::Dispatch do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Dispatch
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Dispatch
    expect(help_response).to respond_to :help
  end

  describe '.tool_calls_from_text' do
    before { PWN::AI::Agent::Registry.discover }

    def args_hash(call)
      raw = call.dig(:function, :arguments)
      raw.is_a?(String) ? JSON.parse(raw, symbolize_names: true) : raw
    end

    it 'parses shell(command="...") kwarg form' do
      calls = described_class.tool_calls_from_text(
        text: 'shell(command="ip addr | head -n 1")'
      )
      expect(calls.length).to eq(1)
      expect(calls[0].dig(:function, :name)).to eq('shell')
      expect(calls[0].dig(:function, :arguments)).to be_a(String)
      expect(args_hash(calls[0])[:command]).to include('ip addr')
    end

    it 'parses shell({JSON}) and bare JSON name/arguments forms' do
      a = described_class.tool_calls_from_text(text: 'shell({"command":"id"})')
      b = described_class.tool_calls_from_text(
        text: '{"name":"shell","arguments":{"command":"uname -a"}}'
      )
      expect(a[0].dig(:function, :arguments)).to be_a(String)
      expect(args_hash(a[0])[:command]).to eq('id')
      expect(args_hash(b[0])[:command]).to eq('uname -a')
    end

    it 'returns [] when no registered tool call is present' do
      expect(
        described_class.tool_calls_from_text(text: 'use hping3 like this: hping3 -1 host')
      ).to eq([])
    end

    it 'parses call:name{...} and tool:name{...} colon-brace forms' do
      a = described_class.tool_calls_from_text(text: 'call:shell{command: "uname -s"}')
      b = described_class.tool_calls_from_text(text: 'tool:shell{"command":"id"}')
      c = described_class.tool_calls_from_text(text: 'call:shell{command="whoami"}')
      expect(a.length).to eq(1)
      expect(a[0].dig(:function, :name)).to eq('shell')
      expect(args_hash(a[0])[:command]).to eq('uname -s')
      expect(args_hash(b[0])[:command]).to eq('id')
      expect(args_hash(c[0])[:command]).to eq('whoami')
    end

    it 'parses JSON objects keyed by tool/call as well as name/function' do
      tool_key = described_class.tool_calls_from_text(
        text: '{"tool":"shell","arguments":{"command":"id"}}'
      )
      call_key = described_class.tool_calls_from_text(
        text: '{"call":"shell","arguments":{"command":"uname -a"}}'
      )
      typed = described_class.tool_calls_from_text(
        text: '{"type":"call","name":"shell","arguments":{"command":"pwd"}}'
      )
      expect(args_hash(tool_key[0])[:command]).to eq('id')
      expect(args_hash(call_key[0])[:command]).to eq('uname -a')
      expect(args_hash(typed[0])[:command]).to eq('pwd')
    end

    it 'ignores prose that only mentions call: without a registered tool body' do
      expect(
        described_class.tool_calls_from_text(text: 'please call:help later')
      ).to eq([])
    end

    it 'parses multi-arg call:name{k=v,...} without swallowing trailing braces' do
      calls = described_class.tool_calls_from_text(
        text: 'call:shell{command=id, timeout=5}'
      )
      expect(calls.length).to eq(1)
      h = args_hash(calls[0])
      expect(h[:command]).to eq('id')
      expect(h[:timeout].to_s).to eq('5')
    end
  end
end
