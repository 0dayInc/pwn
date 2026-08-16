# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TurnFinalizer do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  describe 'user-path depth' do
    after { described_class.leave_user_path! while described_class.user_path? }

    it 'tracks enter/leave and only defers on the user-visible path' do
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false

      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      expect(described_class.user_path?).to be true
      expect(described_class.should_defer?).to be true

      described_class.leave_user_path!
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false
    end

    it 'does not defer when defer_introspect is false' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = false
      expect(described_class.should_defer?).to be false
    end
  end

  describe '.defer' do
    it 'returns immediately and runs Learning.auto_introspect off-thread' do
      seen = Queue.new
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect) do |opts|
        packed = [Thread.current.object_id, opts[:session_id], opts[:inline]]
        seen << packed
        { deferred_ran: true }
      end

      started = Thread.current.object_id
      result = described_class.defer(
        session_id: 'tf_spec',
        request: 'uname',
        final: 'Linux',
        plan: ['probe host']
      )
      expect(result[:deferred]).to be true
      expect(result[:session_id]).to eq('tf_spec')

      described_class.join_all!(timeout: 5)
      tid, sid, inline = seen.pop
      expect(sid).to eq('tf_spec')
      expect(inline).to be true
      expect(tid).not_to eq(started)
    end

    it 'detaches the live Policy episode so maybe_finish_policy is a no-op' do
      allow(PWN::AI::Agent::Policy).to receive(:detach_episode!).and_return({ session_id: 'ep1', steps: [] })
      attached = []
      allow(PWN::AI::Agent::Policy).to receive(:attach_episode!) do |opts|
        attached << opts[:episode]
        opts[:episode]
      end
      allow(PWN::AI::Agent::Policy).to receive(:current_episode).and_return(nil)
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect).and_return({})

      described_class.defer(session_id: 'tf_pol', request: 'x', final: 'y')
      described_class.join_all!(timeout: 5)
      expect(PWN::AI::Agent::Policy).to have_received(:detach_episode!)
      expect(attached.first).to be_a(Hash)
      expect(attached.first[:session_id]).to eq('ep1')
    end
  end

  describe 'Learning.auto_introspect gate' do
    it 'defers when Loop is on the user path' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      PWN::Env[:ai][:agent][:auto_introspect] = true
      allow(described_class).to receive(:defer).and_return({ deferred: true })

      out = PWN::AI::Agent::Learning.auto_introspect(
        session_id: 'tf_gate',
        request: 'hi',
        final: 'ack'
      )
      expect(out[:deferred]).to be true
      expect(described_class).to have_received(:defer)
    ensure
      described_class.leave_user_path! while described_class.user_path?
    end
  end
end
