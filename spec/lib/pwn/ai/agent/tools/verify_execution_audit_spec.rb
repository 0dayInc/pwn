# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'verify file matching through Dispatch' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    PWN::AI::Agent::Registry.discover
  end

  it 'does not verify missing or directory paths as empty files' do
    [File.join(@tmp, 'missing.txt'), @tmp].each do |path|
      response = JSON.parse(PWN::AI::Agent::Dispatch.call(
                              tool_call: { function: { name: 'verify', arguments: JSON.generate(checks: [{ type: 'file_grep', path: path, pattern: '\\A\\z' }]) } }
                            ), symbolize_names: true)

      expect(response.dig(:result, :passed)).to be(false), "incorrect verification for #{path}: #{response}"
      expect(response.dig(:result, :results, 0)).to include(type: 'file_grep', passed: false, path: path)
    end
  end

  it 'can verify an existing empty file with an empty-content expression' do
    path = File.join(@tmp, 'empty.txt')
    File.write(path, '')
    response = JSON.parse(PWN::AI::Agent::Dispatch.call(
                            tool_call: { function: { name: 'verify', arguments: JSON.generate(checks: [{ type: 'file_grep', path: path, pattern: '\\A\\z' }]) } }
                          ), symbolize_names: true)

    expect(response.dig(:result, :passed)).to be true
  end
end
