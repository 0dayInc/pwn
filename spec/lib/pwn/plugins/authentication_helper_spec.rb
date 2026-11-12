# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::AuthenticationHelper do
  it 'prompts for a username with the default label' do
    prompt = instance_double(TTY::Prompt)
    allow(TTY::Prompt).to receive(:new).and_return(prompt)
    expect(prompt).to receive(:ask).with('Username: ').and_return(" fixture-user\n")
    expect(described_class.username).to eq('fixture-user')
  end

  it 'accepts the documented username prompt option' do
    prompt = instance_double(TTY::Prompt)
    allow(TTY::Prompt).to receive(:new).and_return(prompt)
    expect(prompt).to receive(:ask).with('Account: ').and_return('fixture-user')
    expect(described_class.username(prompt: 'Account')).to eq('fixture-user')
  end

  it 'should display information for authors' do
    authors_response = PWN::Plugins::AuthenticationHelper
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::AuthenticationHelper
    expect(help_response).to respond_to :help
  end
end
