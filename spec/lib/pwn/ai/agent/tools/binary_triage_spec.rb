# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'open3'

describe 'PWN::AI::Agent::Tools binary_triage' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/binary_triage.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'binary_triage')).not_to be_nil
  end

  it 'returns mitigations and attack surface from one Dispatch call on a stripped ELF' do
    Dir.mktmpdir('pwn-triage-tool-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      source = File.join(dir, 'fixture.c')
      path = File.join(dir, 'fixture')
      File.write(source, "#include <stdio.h>\nint main(void) { puts(\"https://example.test\"); return 0; }\n")
      out, status = Open3.capture2e('cc', '-O0', '-fstack-protector-all', '-o', path, source)
      expect(status.success?).to eq(true), out
      Open3.capture2e('strip', '--strip-all', path)
      raw = PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'binary_triage', arguments: JSON.generate(path: path, session_id: 'fixture') } }, scope_path: File.join(dir, 'absent.yaml'))
      row = JSON.parse(raw, symbolize_names: true).fetch(:result)
      expect(row[:protections]).to include(:nx, :pie, :relro, :canary, :cfi)
      expect(row[:handle].to_s).to include('fixture/')
      expect(JSON.generate(row[:interesting_strings])).to include('https://example.test')
    end
  end
end
