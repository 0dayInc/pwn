# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Reflect, 'explicit model forwarding' do
  include_context 'pwn tmp sandbox'

  it 'passes a per-call model to the provider even when provider configuration is frozen' do
    PWN::Env[:ai] = { active: :ollama, module_reflection: true, ollama: { model: 'default-model' }.freeze }.freeze
    expect(PWN::AI::Ollama).to receive(:chat).with(hash_including(request: 'fixture input', model: 'teacher-model')).and_return('fixture response')
    expect(described_class.on(request: 'fixture input', model: 'teacher-model', suppress_pii_warning: true)).to eq('fixture response')
    expect(PWN::Env[:ai][:ollama][:model]).to eq('default-model')
    expect(Thread.current[:pwn_reflect_depth]).to be_nil
  end
end
