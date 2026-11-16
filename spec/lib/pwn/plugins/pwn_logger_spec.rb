# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::PWNLogger do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::PWNLogger
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::PWNLogger
    expect(help_response).to respond_to :help
  end

  it 'follows the current $stdout outside rake' do
    previous = ENV.fetch('PWN_RAKE_SPEC', nil)
    ENV.delete('PWN_RAKE_SPEC')
    terminal = StringIO.new
    redirected = StringIO.new
    original = $stdout
    $stdout = terminal
    logger = described_class.create
    $stdout = redirected
    logger.info('Connecting to AWS EC2...')
    expect(terminal.string).not_to include('Connecting to AWS')
    expect(redirected.string).to include('[INFO] Connecting to AWS EC2...')
  ensure
    $stdout = original
    previous.nil? ? ENV.delete('PWN_RAKE_SPEC') : ENV['PWN_RAKE_SPEC'] = previous
  end

  it 'writes nothing during rake, including the pwn logger' do
    previous = ENV.fetch('PWN_RAKE_SPEC', nil)
    ENV['PWN_RAKE_SPEC'] = '1'
    sink = StringIO.new
    original = $stdout
    $stdout = sink
    described_class.create.info('Connecting to AWS EC2...')
    expect(sink.string).to eq('')
  ensure
    $stdout = original
    previous.nil? ? ENV.delete('PWN_RAKE_SPEC') : ENV['PWN_RAKE_SPEC'] = previous
  end
end
