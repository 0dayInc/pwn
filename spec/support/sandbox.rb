# frozen_string_literal: true

require 'tmpdir'
require 'fileutils'

# ─────────────────────────────────────────────────────────────────────────────
#  shared_context 'pwn tmp sandbox'
#
#  Extracts the Dir.mktmpdir + stub_const + PWN::Env dance already used by
#  spec/integration/reinforced_feedback_loop_spec.rb so every functional
#  integration spec is 3 lines of setup:
#
#    RSpec.describe '...' do
#      include_context 'pwn tmp sandbox'
#      it { ... }
#    end
#
#  NON-BLOCKING by construction: every ~/.pwn/* persistence path is redirected
#  into a per-example tmpdir, module_reflection is forced OFF (no LLM calls),
#  MemoryIndex is disabled, and Extrospection ambient probes are stubbed.
#  `rake spec` therefore stays sub-second with no engine, no ~/.pwn writes,
#  and no network / host side-effects.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.shared_context 'pwn tmp sandbox' do
  before do
    @tmp = Dir.mktmpdir('pwn_spec_sandbox')

    # Map every path constant → @tmp iff the owning const/module is loaded.
    # (guarded so a spec that doesn't touch e.g. Reward doesn't pay for it)
    {
      'PWN::Sessions::SESSIONS_DIR' => 'sessions',
      'PWN::Memory::MEMORY_FILE' => 'memory.json',
      'PWN::Cron::CRON_DIR' => 'cron',
      'PWN::Cron::JOBS_FILE' => File.join('cron', 'jobs.yml'),
      'PWN::AI::Agent::Learning::LEARNING_FILE' => 'learning.jsonl',
      'PWN::AI::Agent::Learning::FINETUNE_DIR' => 'finetune',
      'PWN::AI::Agent::Metrics::METRICS_FILE' => 'metrics.json',
      'PWN::AI::Agent::Mistakes::MISTAKES_FILE' => 'mistakes.json',
      'PWN::AI::Agent::Reward::PREFERENCES_FILE' => 'preferences.jsonl',
      'PWN::AI::Agent::Reward::SENTINEL_FILE' => 'sentinel.json',
      'PWN::AI::Agent::Reward::DPO_DIR' => 'finetune',
      'PWN::AI::Agent::Curriculum::CURRICULUM_DIR' => 'curriculum',
      'PWN::AI::Agent::Extrospection::EXTRO_FILE' => 'extrospection.json',
      'PWN::AI::Agent::Swarm::AGENTS_FILE' => 'agents.yml',
      'PWN::AI::Agent::Swarm::SWARM_ROOT' => 'swarm'
    }.each do |const, rel|
      owner = const.split('::')[0..-2].join('::')
      stub_const(const, File.join(@tmp, rel)) if Object.const_defined?(owner)
    end
    stub_const('PWN::MemoryIndex::INDEX_FILE', File.join(@tmp, 'memory.idx')) if defined?(PWN::MemoryIndex)

    # Controllable env — module_reflection OFF so nothing hits an engine.
    @agent_cfg = {}
    @env_prev  = PWN::Env[:ai]
    PWN::Env[:ai] = { active: :ollama, module_reflection: false, agent: @agent_cfg }

    # Kill every side-channel that could block / touch the real host.
    allow(PWN::MemoryIndex).to receive(:available?).and_return(false) if defined?(PWN::MemoryIndex)
    if defined?(PWN::AI::Agent::Extrospection)
      allow(PWN::AI::Agent::Extrospection).to receive(:auto_extrospect).and_return(nil)
      allow(PWN::AI::Agent::Extrospection).to receive(:drift).and_return(changed: [], added: [], removed: [])
    end

    Thread.current[:pwn_pending_pref] = nil
    Thread.current[:pwn_curriculum]   = nil
    Thread.current[:pwn_swarm_depth]  = nil
  end

  after do
    PWN::Env[:ai] = @env_prev
    Thread.current[:pwn_pending_pref] = nil
    Thread.current[:pwn_curriculum]   = nil
    Thread.current[:pwn_swarm_depth]  = nil
    FileUtils.remove_entry(@tmp) if @tmp && Dir.exist?(@tmp)
  end
end
