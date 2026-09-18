# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'json'

describe 'PWN::AI::Agent::Tools sandbox strict' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/shell.rb'
    load '/opt/pwn/lib/pwn/ai/agent/tools/ruby_eval.rb'
  end

  it 'raises a sandbox violation for shell rm and pwn_eval FileUtils.rm_rf without touching disk' do
    root = '/tmp/fake_root'
    FileUtils.mkdir_p(root)
    marker = File.join(root, 'keep')
    File.write(marker, 'safe')
    begin
      stub_const('PWN::Env', { ai_sandbox: 'strict' })
      shell = PWN::AI::Agent::Dispatch.call(
        tool_call: { function: { name: 'shell', arguments: JSON.generate(command: 'rm -rf /tmp/fake_root') } },
        scope_path: File.join(Dir.tmpdir, 'absent.yaml')
      )
      ruby = PWN::AI::Agent::Dispatch.call(
        tool_call: { function: { name: 'pwn_eval', arguments: JSON.generate(code: "FileUtils.rm_rf('/tmp/fake_root')") } },
        scope_path: File.join(Dir.tmpdir, 'absent.yaml')
      )
      expect(JSON.parse(shell, symbolize_names: true).fetch(:result)[:error].to_s).to match(/sandbox violation/i)
      expect(JSON.parse(ruby, symbolize_names: true).fetch(:result)[:error].to_s).to match(/sandbox violation/i)
      expect(File.file?(marker)).to be true
    ensure
      FileUtils.rm_rf(root)
    end
  end
end
