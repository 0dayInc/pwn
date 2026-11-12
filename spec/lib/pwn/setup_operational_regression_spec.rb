# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Setup operational checks' do
  include_context 'pwn tmp sandbox'

  before { allow(Dir).to receive(:home).and_return(@tmp) }

  it 'does not request interactive confirmation for a terminal dry run' do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('TERMINATOR_UUID').and_return('fixture-terminal')
    expect($stdin).not_to receive(:gets)
    result = PWN::Setup.terminal(dry_run: true, io: StringIO.new)
    expect(result).to include(installed: false, reason: :dry_run)
    expect(File).not_to exist(File.join(@tmp, '.config', 'terminator'))
  end

  it 'checks only the selected profile after planning its dependencies' do
    allow(PWN::Setup).to receive(:pkg_manager).and_return(key: :apt, install: 'fixture-install', sudo: false)
    allow(PWN::Setup).to receive(:gem_loadable?).and_return(true)
    allow(PWN::Setup).to receive(:native_library_available?).and_return(false)
    allow(PWN::Setup).to receive(:which).and_return('')
    allow(PWN::Migrate).to receive(:check).and_return(incompatible: [])
    expect(PWN::Setup).not_to receive(:system)
    result = PWN::Setup.deps(profile: :core, distro: :debian, version: 'fixture', dry_run: true, io: StringIO.new)
    expect(result.dig(:check, :ok)).to be(true)
  end

  it 'does not mistake template key descriptions for configured authentication' do
    PWN::Env[:ai][:grok] = { key: 'required - xAI Grok API Key' }
    expect(PWN::Setup.send(:ai_key_configured?, engine: :grok)).to be(false)
    PWN::Env[:ai][:grok][:key] = 'synthetic-fixture-key'
    expect(PWN::Setup.send(:ai_key_configured?, engine: :grok)).to be(true)
  end
end
