# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'SAST filter edge regressions' do
  around do |example|
    Dir.mktmpdir('pwn-sast-filters-') do |dir|
      @source_dir = dir
      example.run
    end
  end

  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    allow(PWN::AI::Agent::SAST).to receive(:analyze).and_return(nil)
  end

  it 'preserves the original Keystore scan exception' do
    error = IOError.new('fixture scan failure')
    allow(PWN::SAST::TestCaseEngine).to receive(:execute).and_raise(error)
    expect { PWN::SAST::Keystore.scan(dir_path: @source_dir) }.to(raise_error { |actual| expect(actual).to equal(error) })
  end

  { PHPTypeJuggling: '.php', TypeScriptTypeJuggling: '.ts' }.each do |name, extension|
    it "detects loose comparisons on mixed strict/loose lines in #{name}" do
      File.write(File.join(@source_dir, "source#{extension}"), "a === b || c == d\na !== b && c != d\na === b\na !== b\n")
      result = PWN::SAST.const_get(name).scan(dir_path: @source_dir)
      expect(result.length).to eq(1)
      expect(result.first[:line_no_and_contents].map { |line| line[:line_no] }).to eq(%w[1 2])
    end
  end

  it 'retains SQL candidates because placeholder text does not establish safe binding' do
    File.write(File.join(@source_dir, 'source.txt'), "#{"\n" * 10}SELECT name FROM users WHERE id = ?\nSELECT name FROM users WHERE id = :x\nSELECT name FROM users\n")
    result = PWN::SAST::SQL.scan(dir_path: @source_dir)
    expect(result.first[:line_no_and_contents].map { |line| line[:line_no] }).to eq(%w[11 12 13])
  end
end
