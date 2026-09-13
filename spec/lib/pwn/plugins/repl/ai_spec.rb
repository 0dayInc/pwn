# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AI do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL::AI
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL::AI
    expect(help_response).to respond_to :help
  end

  it 'registers the pwn-ai Pry command' do
    expect(described_class).to respond_to :add_commands
    described_class.add_commands
    expect(Pry::Commands.find_command('pwn-ai')).not_to be_nil
  end
end
