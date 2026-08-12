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

  describe '.env_template AI providers' do
    let(:ai) { described_class.env_template[:ai] }

    it 'includes ollama and openwebui provider slots' do
      expect(ai).to include(:ollama, :openwebui)
      expect(ai[:ollama]).to be_a(Hash)
      expect(ai[:openwebui]).to be_a(Hash)
    end

    it 'marks ollama key optional (stock ollama needs none)' do
      key = ai[:ollama][:key].to_s
      expect(key).to match(/\Aoptional\b/i)
      expect(ai[:ollama][:base_uri].to_s).to match(/11434|optional/i)
      expect(ai[:ollama][:model]).not_to be_nil
    end

    it 'requires openwebui base_uri, key, and model' do
      expect(ai[:openwebui][:base_uri].to_s).to match(/\Arequired\b/i)
      expect(ai[:openwebui][:key].to_s).to match(/\Arequired\b/i)
      expect(ai[:openwebui][:model].to_s).to match(/\Arequired\b/i)
    end
  end

  describe '.merge_ai_defaults! (private)' do
    it 'backfills missing :ollama and :openwebui hashes when active points at them' do
      env = { ai: { active: 'ollama', agent: {} } }
      described_class.send(:merge_ai_defaults!, env: env)
      expect(env[:ai][:ollama]).to be_a(Hash)
      expect(env[:ai][:ollama]).to include(:base_uri, :model, :key)
      expect(env[:ai][:openwebui]).to be_a(Hash)
      expect(env[:ai][:openwebui]).to include(:base_uri, :key, :model)
    end

    it 'does not overwrite operator-provided engine values' do
      env = {
        ai: {
          active: 'openwebui',
          openwebui: { base_uri: 'https://owu.example', key: 'sk-test', model: 'm1' }
        }
      }
      described_class.send(:merge_ai_defaults!, env: env)
      expect(env[:ai][:openwebui][:base_uri]).to eq 'https://owu.example'
      expect(env[:ai][:openwebui][:key]).to eq 'sk-test'
      expect(env[:ai][:openwebui][:model]).to eq 'm1'
      # absent keys filled
      expect(env[:ai][:openwebui][:num_ctx]).not_to be_nil
    end
  end

  describe 'refresh_env API-key prompt policy (source contract)' do
    let(:src) { File.read(described_class.method(:refresh_env).source_location.first) }

    it 'skips API key prompt when active engine is :ollama' do
      expect(src).to match(/if engine != :ollama/)
      # Ollama must not be in enroll_hints (those engines may prompt)
      expect(src).to include('enroll_hints')
      expect(src).not_to match(/enroll_hints = \{[^}]*ollama:/m)
    end

    it 'still allows openwebui key solicitation (not in ollama skip)' do
      # openwebui is intentionally NOT treated like ollama
      expect(src).to include('openwebui still requires a JWT/API key')
    end

    it 'rejects REDACTED / placeholder keys in real_cfg' do
      expect(src).to match(/REDACTED/i)
      expect(src).to match(/optional\|required/)
    end
  end
end
