# frozen_string_literal: true

require_relative 'fake_provider'

# Observers forward to the real public APIs; neither retrieval nor training is
# replaced. Counts mean executions, not estimated learning activity or gain.
observed = Hash.new(0)
[[PWN::AI::Agent::Learning, :to_context, :learning_context_calls],
 [PWN::AI::Agent::Policy, :begin_episode, :policy_begin_calls],
 [PWN::AI::Agent::Swarm, :ask, :swarm_ask_calls]].each do |target, method, key|
  target.singleton_class.prepend(Module.new do
    define_method(method) do |opts = {}|
      observed[key] += 1
      super(opts)
    end
  end)
end
at_exit do
  File.write(ENV.fetch('PWN_HARNESS_OBSERVATIONS'), JSON.generate(observed))
end
