# frozen_string_literal: true

require 'spec_helper'

describe PWN::Config do
  it 'should display information for authors' do
    authors_response = PWN::Config
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Config
    expect(help_response).to respond_to :help
  end
end

it 'should respond to pwn_skills_path' do
  expect(PWN::Config).to respond_to :pwn_skills_path
end

it 'should respond to load_skills and create/return skills hash' do
  expect(PWN::Config).to respond_to :load_skills
  skills = PWN::Config.load_skills
  expect(skills).to be_a(Hash)
end
