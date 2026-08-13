# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::ToolGuard do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::ToolGuard
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::ToolGuard
    expect(help_response).to respond_to :help
  end

  describe '.present?' do
    it 'is true for a non-empty string' do
      expect(described_class.present?(value: 'id')).to be true
    end

    it 'is false for nil, blank, and whitespace' do
      expect(described_class.present?(value: nil)).to be false
      expect(described_class.present?(value: '')).to be false
      expect(described_class.present?(value: '   ')).to be false
    end
  end

  describe '.placeholder?' do
    it 'matches ellipsis placeholders' do
      expect(described_class.placeholder?(text: '...')).to be true
      expect(described_class.placeholder?(text: '{...}')).to be true
    end

    it 'rejects a real command' do
      expect(described_class.placeholder?(text: 'uname -r')).to be false
    end
  end

  describe '.coerce_args' do
    it 'aliases value onto the first required key' do
      args = described_class.coerce_args(args: { value: 'id' }, required: %w[command])
      expect(args[:command]).to eq('id')
      expect(args[:__schema_error]).to be_nil
    end

    it 'sets __schema_error when the required key is still missing' do
      args = described_class.coerce_args(args: {}, required: %w[command])
      expect(args[:__schema_error]).to include('command')
      expect(args[:__schema_hint]).to include('Expected keys')
    end
  end

  describe '.invalid_payload' do
    it 'returns exit 2 and error invalid_payload' do
      out = described_class.invalid_payload(hint: 'missing required command')
      expect(out[:exit]).to eq(2)
      expect(out[:error]).to eq('invalid_payload')
      expect(out[:stderr]).to include('missing required command')
    end
  end
end
