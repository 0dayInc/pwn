# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::MonkeyPatch do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::MonkeyPatch
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::MonkeyPatch
    expect(help_response).to respond_to :help
  end

  it 'can install twice without replacing the original expression parser with its wrapper' do
    require 'open3'
    program = <<~RUBY
      require 'pwn'
      require 'pry'
      2.times { PWN::Plugins::MonkeyPatch.pry }
      parser = Object.new.extend(MethodSource::CodeHelpers)
      raise 'complete expression rejected' unless parser.complete_expression?('1 + 1')
      raise 'incomplete expression accepted' if parser.complete_expression?('def fixture')
      puts 'repeated installation preserves parser'
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-Ilib', '-e', program)
    expect(status.success?).to be(true), stderr
    expect(stdout).to eq("repeated installation preserves parser\n")
  end

  it 'routes CTRL+D in pwn-ai to leave_special_mode instead of exiting Pry' do
    src = File.read(described_class.method(:pry).source_location.first)
    expect(src).to include('leave_special_mode!')
    expect(src).to include('config.pwn_ai')
    expect(src).to include('control_d_handler')
  end
end
