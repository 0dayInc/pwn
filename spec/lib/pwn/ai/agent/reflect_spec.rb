# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Reflect do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Reflect
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Reflect
    expect(help_response).to respond_to :help
  end

  describe 'RL stack contracts' do
    it 'Reflect.on never nests Loop.run (uses engine_chat only)' do
      src = File.read(described_class.method(:on).source_location.first)
      # Executable call-sites only: drop pure comment lines and quoted docs.
      bare = src.lines.grep_v(/^\s*#/)
                .grep(/Loop\.run\s*\(/)
      expect(bare).to be_empty
      expect(src).to match(/def self\.engine_chat/)
      expect(src).to match(/pwn_reflect_depth/)
      expect(src).to match(/engine_chat\b/)
      # Implementation note documents the contract
      expect(src).to match(/never\s+Loop\.run|MUST call the engine/i)
    end

    it 'engine_chat is private and talks to provider .chat APIs only' do
      expect(described_class.respond_to?(:engine_chat)).to be false
      expect(described_class.respond_to?(:engine_chat, true)).to be true
      src = File.read(described_class.method(:on).source_location.first)
      chat_body = src[/private_class_method def self\.engine_chat.*?(?=private_class_method def self\.|public_class_method def self\.authors)/m]
      expect(chat_body || src).to match(/\.chat\b/)
      bare = (chat_body || src).lines.grep_v(/^\s*#/).grep(/Loop\.run\s*\(/)
      expect(bare).to be_empty
    end
  end
end
