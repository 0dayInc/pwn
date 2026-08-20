# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

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

  describe '.host_load / .deadline_s' do
    it 'reports load1, ncpu, and mem_avail_mb' do
      snap = described_class.host_load
      expect(snap[:ncpu].to_i).to be >= 1
      expect(snap[:load1]).to be_a(Numeric)
      expect(snap[:mem_avail_mb].to_i).to be >= 0
    end

    it 'clamps an explicit timeout and derives a default when omitted' do
      expect(described_class.deadline_s(timeout: 1, kind: :eval)).to eq(1)
      expect(described_class.deadline_s(timeout: 9_999, kind: :eval)).to eq(90)
      expect(described_class.deadline_s(timeout: 9_999, kind: :shell)).to eq(180)
      omitted = described_class.deadline_s(kind: :eval)
      expect(omitted).to be_between(8, 90)
    end
  end

  describe '.timeout_lesson' do
    it 'prefers reconstruct-the-payload before raising timeout' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      first = described_class.timeout_lesson(tool: 'pwn_eval', payload: 'sleep 3', timeout: 1)
      expect(first[:scenario]).to eq(:construction)
      expect(first[:hint]).to match(/reconstruct|generated differently|improperly/i)
      expect(first[:hint]).to match(/do not first raise timeout/i)
      expect(first[:error]).to match(/reconstruct/)
    end

    it 'switches to deadline-too-short only after a prior timeout mistake' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      PWN::AI::Agent::Mistakes.record(
        tool: 'shell',
        error: 'shell timeout: reconstruct payload to same goal before raising timeout',
        args: 'sleep 3',
        source: :tool,
        shape: :timeout
      )
      second = described_class.timeout_lesson(tool: 'shell', payload: 'sleep 3', timeout: 1)
      expect(second[:scenario]).to eq(:deadline)
      expect(second[:hint]).to match(/timeout was too short|deadline too short|raise a conservative/i)
      expect(second[:error]).to match(/too short/)
    end
  end
end
