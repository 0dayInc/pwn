# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::PromptCache do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  let(:prompt) do
    [
      'You are a pwn agent.',
      '',
      'ENVIRONMENT',
      '  host       : kali',
      '  session_id : abc',
      '',
      'SKILLS (call skill_view to read full body)',
      '  - nmap: scan hosts [2 refs]',
      '',
      'MEMORY',
      '  - fact: something turn-local',
      '',
      'LEARNING',
      '  recent outcomes',
      '',
      'TOOL USE',
      '  Use the provided function tools',
      ''
    ].join("\n")
  end

  describe '.split_system' do
    it 'keeps persona + ENVIRONMENT + SKILLS in the static prefix' do
      parts = described_class.split_system(text: prompt)
      expect(parts[:static]).to include('You are a pwn agent')
      expect(parts[:static]).to include('ENVIRONMENT')
      expect(parts[:static]).to include('SKILLS')
      expect(parts[:static]).not_to include('MEMORY')
      expect(parts[:dynamic]).to include('MEMORY')
      expect(parts[:dynamic]).to include('LEARNING')
      expect(parts[:dynamic]).to include('TOOL USE')
    end
  end

  describe '.anthropic_system_blocks' do
    it 'marks the static prefix with an ephemeral cache breakpoint' do
      blocks = described_class.anthropic_system_blocks(text: prompt)
      expect(blocks.length).to eq(2)
      expect(blocks[0][:type]).to eq('text')
      expect(blocks[0][:cache_control]).to eq(type: 'ephemeral')
      expect(blocks[0][:text]).to include('SKILLS')
      expect(blocks[1][:cache_control]).to be_nil
      expect(blocks[1][:text]).to include('MEMORY')
      expect(described_class.cache_marks(blocks: blocks)).to eq(1)
    end
  end

  describe '.enabled?' do
    it 'is on for anthropic, openai, grok, and gemini when prompt_cache is true' do
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:prompt_cache] = true
      expect(described_class.enabled?(engine: :anthropic)).to be true
      expect(described_class.enabled?(engine: :openai)).to be true
      expect(described_class.enabled?(engine: :grok)).to be true
      expect(described_class.enabled?(engine: :gemini)).to be true
      expect(described_class.enabled?(engine: :ollama)).to be false
    end

    it 'is off for every engine when prompt_cache is false' do
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:prompt_cache] = false
      expect(described_class.enabled?(engine: :anthropic)).to be false
      expect(described_class.enabled?(engine: :openai)).to be false
      expect(described_class.enabled?(engine: :grok)).to be false
      expect(described_class.enabled?(engine: :gemini)).to be false
    end
  end

  describe '.openai_messages' do
    it 'splits the first system message into static then dynamic' do
      msgs = described_class.openai_messages(
        messages: [{ role: 'system', content: prompt }, { role: 'user', content: 'hi' }]
      )
      expect(msgs.length).to eq(3)
      expect(msgs[0][:content]).to include('SKILLS')
      expect(msgs[0][:content]).not_to include('MEMORY')
      expect(msgs[1][:role]).to eq('system')
      expect(msgs[1][:content]).to include('MEMORY')
      expect(msgs[2][:role]).to eq('user')
    end
  end

  describe '.gemini_system_instruction' do
    it 'emits two parts without Anthropic cache_control' do
      inst = described_class.gemini_system_instruction(text: prompt)
      expect(inst[:parts].length).to eq(2)
      expect(inst[:parts][0][:text]).to include('SKILLS')
      expect(inst[:parts][1][:text]).to include('MEMORY')
      expect(inst[:parts][0][:cache_control]).to be_nil
    end
  end

  describe '.cache_key' do
    it 'is stable across dynamic MEMORY changes' do
      a = described_class.cache_key(text: prompt)
      b = described_class.cache_key(text: prompt.sub('something turn-local', 'other fact'))
      expect(a).to eq(b)
      expect(a).to match(/\Apwn-[0-9a-f]{24}\z/)
    end
  end
end
