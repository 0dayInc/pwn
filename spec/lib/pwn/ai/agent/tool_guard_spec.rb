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

    it 'honors any explicit timeout up to 3 hours and derives a default when omitted' do
      expect(described_class.deadline_s(timeout: 1, kind: :eval)).to eq(1)
      expect(described_class.deadline_s(timeout: 300, kind: :eval)).to eq(300)
      expect(described_class.deadline_s(timeout: 3_600, kind: :shell)).to eq(3_600)
      expect(described_class.deadline_s(timeout: 99_999, kind: :eval)).to eq(10_800)
      omitted = described_class.deadline_s(kind: :eval)
      expect(omitted).to be_between(8, 90)
    end

    it 'does not sniff payloads for named tools' do
      src = File.read(described_class.method(:deadline_s).source_location.first)
      expect(src).not_to match(/\bnmap\b/i)
      expect(src).not_to match(/\bsqlmap\b/i)
      expect(src).not_to match(/\bhydra\b/i)
      expect(described_class).not_to respond_to(:long_work?)
    end
  end

  describe '.next_timeout' do
    it 'adds 180 seconds until the 3-hour cap' do
      expect(described_class.next_timeout(timeout: 60)).to eq(240)
      expect(described_class.next_timeout(timeout: 180)).to eq(360)
      expect(described_class.next_timeout(timeout: 10_800)).to eq(10_800)
    end
  end

  describe '.timeout_lesson' do
    before do
      described_class.reset_timeout_budget!
    end

    it 'increments timeout on the same payload before rewriting' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      first = described_class.timeout_lesson(
        tool: 'pwn_eval',
        payload: 'sleep 3',
        timeout: 180,
        task: 't1'
      )
      expect(first[:scenario]).to eq(:deadline)
      expect(first[:hint]).to match(/timeout \+= 180|next_timeout/i)
      expect(first[:hint]).not_to match(/reconstruct/i)
      expect(described_class.next_timeout(timeout: 180, spent: 180)).to eq(360)
    end

    it 'rewrites the payload only after the 3-hour budget is exhausted' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      described_class.note_timeout!(
        tool: 'shell',
        payload: 'sleep 3',
        timeout: 10_800,
        task: 't1'
      )
      lesson = described_class.timeout_lesson(
        tool: 'shell',
        payload: 'sleep 3',
        timeout: 10_800,
        task: 't1'
      )
      expect(lesson[:scenario]).to eq(:construction)
      expect(lesson[:hint]).to match(/3-hour budget|Generate different/i)
      expect(described_class.mutation_count(task: 't1')).to eq(1)
    end

    it 'stops after 10 mutations on the same task' do
      10.times do |i|
        described_class.note_timeout!(
          tool: 'shell',
          payload: "payload-#{i}",
          timeout: 10_800,
          task: 't1'
        )
      end
      last = described_class.timeout_lesson(
        tool: 'shell',
        payload: 'payload-9',
        timeout: 10_800,
        task: 't1'
      )
      expect(described_class.mutation_count(task: 't1')).to eq(10)
      expect(last[:scenario]).to eq(:exhausted)
      expect(last[:hint]).to match(/10 mutations|mutation cap/i)
    end

    it 'includes next_timeout on a mid-budget timeout result' do
      out = described_class.timeout_result(
        tool: 'shell',
        payload: 'sleep 3',
        timeout: 180,
        task: 't1'
      )
      expect(out[:scenario]).to eq(:deadline)
      expect(out[:next_timeout]).to eq(360)
    end
  end
end
