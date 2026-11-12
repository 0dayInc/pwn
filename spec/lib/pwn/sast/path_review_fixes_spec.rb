# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'

RSpec.describe 'SAST explicit test-path convention' do
  around do |example|
    Dir.mktmpdir('pwn-path-review-') do |dir|
      @sources = dir
      example.run
    end
  end

  before { stub_const('PWN::Env', { ai: { module_reflection: false } }) }

  def write_source(name, contents)
    path = File.join(@sources, name)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, contents)
  end

  def execute(extra = {})
    options = { dir_path: @sources, security_references: { sast_module: 'Fixture' },
                test_case_filter: 'grep -n -e fixture {PWN_SAST_SRC_TARGET}' }.merge(extra).freeze
    PWN::SAST::TestCaseEngine.execute(options)
  end

  it 'SERVICES-REVIEW-005 retains production paths with incidental test substrings in actual Logger scans' do
    names = ['contest.rb', 'latest.js', 'latest_release/service.rb', 'testimony.rb']
    names.each { |name| write_source(name, "#{"\n" * 20}logger.info(password);\n") }

    expect(PWN::SAST::Logger.scan(dir_path: @sources).map { |row| row[:filename][:entry] }).to match_array(names.map { |name| "./#{name}" })
  end

  it 'SERVICES-REVIEW-005 excludes only explicit directory and filename conventions' do
    names = %w[test/source.rb tests/source.rb spec/source.rb specs/source.rb __tests__/source.rb src/test_source.rb src/source_test.rb src/source_spec.rb src/source.test.js src/source.spec.js]
    names.each { |name| write_source(name, "#{"\n" * 20}fixture\n") }

    expect(execute).to eq([])
    expect(execute(exclude_test_paths: false).map { |row| row[:filename][:entry] }).to match_array(names.map { |name| "./#{name}" })
  end

  it 'SERVICES-REVIEW-005 retains PomVersion production paths but excludes explicit test directories' do
    %w[contest latest_release tests spec __tests__].each { |name| write_source("#{name}/pom.xml", "<version>1.2.3</version>\n") }

    result = PWN::SAST::PomVersion.scan({ dir_path: @sources }.freeze)

    expect(result.map { |row| row[:filename][:entry] }).to match_array(%w[./contest/pom.xml ./latest_release/pom.xml])
    expect(result.map { |row| row[:line_no_and_contents].first[:line_no] }).to eq(%w[1 1])
  end

  it 'SERVICES-REVIEW-005 allows explicit inclusion of test paths in PomVersion' do
    write_source('tests/pom.xml', "<version>1.2.3</version>\n")
    options = { dir_path: @sources, exclude_test_paths: false }.freeze

    expect(PWN::SAST::PomVersion.scan(options).map { |row| row[:filename][:entry] }).to eq(['./tests/pom.xml'])
    expect(options).to eq(dir_path: @sources, exclude_test_paths: false)
  end
end
