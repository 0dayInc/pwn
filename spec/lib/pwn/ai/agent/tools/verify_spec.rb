# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools verify' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/verify.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'verify')).not_to be_nil
  end

  it 'passes file_exists when the path is on disk' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x')
      File.write(path, 'ok')
      out = PWN::AI::Agent::Registry.lookup(name: 'verify').handler.call(checks: [{ type: 'file_exists', path: path }])
      expect(out[:passed]).to be true
    end
  end
end
