# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL
    expect(help_response).to respond_to :help
  end

  it 'appends plan usage after the token budget in the pwn.ai PS1' do
    src = File.read(described_class.method(:refresh_ps1_proc).source_location.first)
    expect(src).to include('PWN::AI.plan_usage_glyph(engine: engine)')
    expect(src).to include("\#{current_context_length}/\#{plan_usage_glyph}")
  end

  it 'formats compact token counts for the PS1 budget' do
    expect(described_class.compact_context_tokens(tokens: 0)).to eq('0')
    expect(described_class.compact_context_tokens(tokens: 26_000)).to eq('26K')
    expect(described_class.compact_context_tokens(tokens: 500_000)).to eq('500K')
  end

  it 'ready_tty! exists and the pwn-ai path resets the TTY before the next PS1' do
    expect(described_class).to respond_to :ready_tty!
    hook = File.read(described_class.method(:add_hooks).source_location.first)
    expect(hook).to match(/ready_tty!/)
    expect(hook).to match(/request\.replace\('nil'\)/)
    reader = File.read(described_class.const_get(:PWNMultiLineInput).instance_method(:readline).source_location.first)
    expect(reader).to match(/ready_tty!/)
  end
end
