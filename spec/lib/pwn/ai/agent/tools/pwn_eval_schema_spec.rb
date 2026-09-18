# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools pwn_eval plugin schema' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/ruby_eval.rb'
  end

  it 'rejects an unknown plugin keyword before eval and echoes the schema' do
    raw = PWN::AI::Agent::Dispatch.call(
      tool_call: {
        function: {
          name: 'pwn_eval',
          arguments: JSON.generate(code: 'PWN::Plugins::BasicAuth.encode(not_a_key: 1)')
        }
      },
      scope_path: File.join(Dir.tmpdir, 'absent.yaml')
    )
    row = JSON.parse(raw, symbolize_names: true).fetch(:result)
    expect(row[:error].to_s).to match(/unknown keyword/i)
    expect(row[:schema]).to be_a(Hash)
  end
end
