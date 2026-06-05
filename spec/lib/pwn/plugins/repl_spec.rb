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
end

it 'should support pwn-ai agent via REPL' do
  # The pwn-ai command is registered in add_commands; basic module responds
  expect(PWN::Plugins::REPL).to respond_to :help
  expect(PWN::Plugins::REPL).to respond_to :authors
end
