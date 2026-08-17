# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Policy is the LIVE tabular RL controller that
      # pwn-ai did not have before R5. Everything else in the harness is
      # retrieval-plus-policy: scores are written to disk and re-injected
      # as prose, or exported later for optional LoRA. This module is the
      # missing MDP:
      #
      #   state  s  — discretized (kind, task, plan, completeness, usable, last, fail)
      #   action a  — tool name, or "final"
      #   reward r  — step: semantic_ok hygiene; terminal: Reward.judge
      #   next   s' — state after the tool result
      #
      # Each Loop turn is one episode. Transitions land in
      # ~/.pwn/policy_traj.jsonl. Q(s,a) and REINFORCE logits H(s,a) are
      # updated from those tuples and persisted in ~/.pwn/policy.json.
      #
      # The learned Q values are an ADVISORY term in Registry.rank. They
      # never replace TaskSummarizer planning, plan_first, or CORE_TOOLS.
      # Disable with PWN::Env[:ai][:agent][:policy] = false.
      module Policy
        POLICY_FILE     = File.join(Dir.home, '.pwn', 'policy.json')
        TRAJECTORY_FILE = File.join(Dir.home, '.pwn', 'policy_traj.jsonl')

        ALPHA      = 0.15
        ALPHA_PG   = 0.05
        GAMMA      = 0.85
        EPSILON    = 0.08
        STEP_OK    = 0.05
        STEP_FAIL  = -0.20
        MAX_TRAJ   = 2_000
        GOLD_MIN   = 0.6
        VISITS_MIN = 2
        COLD_EPISODES = 8
        WARM_EPISODES = 40
        TASK_MOD   = 16
        ACTION_MOD = 16
        EP_KEY     = :pwn_policy_episode

        # ----------------------------------------------------------------
        # Feature → discrete state
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # key = PWN::AI::Agent::Policy.state(
        #   kind: 'optional - statement|question|autonomous_goal|…',
        #   request: 'optional - user text / active English task',
        #   last_action: 'optional - previous tool name',
        #   fails: 'optional - in-turn failure count',
        #   engine: 'optional - active engine'
        # )

        public_class_method def self.state(opts = {})
          kind = normalize_kind(raw: opts[:kind] || opts[:request_kind])
          task = task_family(text: opts[:task] || opts[:request])
          eng  = opts[:engine].to_s.empty? ? 'any' : opts[:engine].to_s.downcase
          plan_q = plan_quality_bin(ts_state: opts[:ts_state])
          comp = completeness_bin(final: opts[:final], score: opts[:score])
          use = usable_bin(final: opts[:final], score: opts[:score])
          # Three independent bins so Q can see plan quality, answer
          # completeness, and whether the human actually got a usable result.
          qual = "p#{plan_q}c#{comp}u#{use}"
          if warm?
            last = action_bucket(name: opts[:last_action] || opts[:last] || 'start')
            fail = fail_bin(count: opts[:fails] || opts[:fail_n])
            "#{kind}|#{task}|a#{last}|f#{fail}|#{qual}|#{eng}"
          elsif !cold?
            fail = fail_bin(count: opts[:fails] || opts[:fail_n])
            "#{kind}|#{task}|f#{fail}|#{qual}|#{eng}"
          else
            "#{kind}|#{task}|#{qual}|#{eng}"
          end
        end

        public_class_method def self.cold?
          stats[:n_episodes].to_i < COLD_EPISODES
        rescue StandardError
          true
        end

        public_class_method def self.warm?
          stats[:n_episodes].to_i >= WARM_EPISODES
        rescue StandardError
          false
        end

        # True once live returns, warmup-replayed trajectories, or a
        # warmed Q table have enough mass to emit greedy suggestions.
        # Cold? stays a coarser state-encoding gate; this is the banner.
        public_class_method def self.episode_budget_met?
          n = stats[:n_episodes].to_i
          return true if n >= COLD_EPISODES

          tab = load
          warmed = !tab[:warmed_at].to_s.empty?
          pairs = 0
          tab[:q].each_value { |acts| pairs += acts.length if acts.is_a?(Hash) }
          return true if warmed && pairs >= COLD_EPISODES

          traj_n = trajectories(limit: COLD_EPISODES).length
          warmed && traj_n >= COLD_EPISODES
        rescue StandardError
          false
        end

        # ----------------------------------------------------------------
        # Episode / environment loop
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # ep = PWN::AI::Agent::Policy.begin_episode(
        #   session_id: 'optional - PWN::Sessions id',
        #   request: 'optional - user request',
        #   kind: 'optional - request kind',
        #   intent: 'optional - Loop.request_intent',
        #   engine: 'optional - active engine',
        #   ts_state: 'optional - TaskSummarizer state hash'
        # )

        public_class_method def self.begin_episode(opts = {})
          return { skipped: :disabled } unless enabled?

          sid = (opts[:session_id] || "ep_#{Thread.current.object_id}").to_s
          task = active_task_text(ts_state: opts[:ts_state], request: opts[:request])
          s0 = state(
            kind: opts[:kind],
            request: task,
            last_action: 'start',
            fails: 0,
            engine: opts[:engine],
            ts_state: opts[:ts_state]
          )
          ep = {
            session_id: sid,
            request: opts[:request].to_s[0, 240],
            kind: normalize_kind(raw: opts[:kind]),
            intent: opts[:intent].to_s,
            engine: opts[:engine].to_s,
            started_at: Time.now.utc.iso8601,
            state: s0,
            last_action: 'start',
            fails: 0,
            steps: []
          }
          Thread.current[EP_KEY] = ep
          ep
        rescue StandardError => e
          warn "[pwn-ai/policy] begin_episode swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # step = PWN::AI::Agent::Policy.observe_step(
        #   session_id: 'optional - must match begin_episode when set',
        #   action: 'required - tool name',
        #   ok: 'required - Boolean, Reward.semantic_ok',
        #   duration: 'optional - Float seconds',
        #   ts_state: 'optional - TaskSummarizer state',
        #   request: 'optional - used if episode was not begun',
        #   kind: 'optional',
        #   engine: 'optional'
        # )

        public_class_method def self.observe_step(opts = {})
          return { skipped: :disabled } unless enabled?

          action = opts[:action].to_s
          return { skipped: :no_action } if action.empty?

          ep = Thread.current[EP_KEY]
          if ep.nil? || (opts[:session_id] && ep[:session_id] && opts[:session_id].to_s != ep[:session_id].to_s)
            begin_episode(
              session_id: opts[:session_id],
              request: opts[:request],
              kind: opts[:kind],
              engine: opts[:engine],
              ts_state: opts[:ts_state]
            )
            ep = Thread.current[EP_KEY]
          end
          return { skipped: :no_episode } unless ep.is_a?(Hash)

          ok = opts[:ok] ? true : false
          ep[:fails] = ep[:fails].to_i + 1 unless ok
          distrust = 0.0
          distrust = Reward.proxy_distrust.to_f if defined?(Reward) && Reward.respond_to?(:proxy_distrust)
          reward = if distrust >= 0.85
                     0.0
                   else
                     ok ? STEP_OK : STEP_FAIL
                   end
          s = ep[:state]
          task = active_task_text(ts_state: opts[:ts_state], request: ep[:request])
          s2 = state(
            kind: ep[:kind],
            request: task,
            last_action: action,
            fails: ep[:fails],
            engine: ep[:engine],
            ts_state: opts[:ts_state]
          )
          trans = {
            state: s,
            action: action,
            reward: reward,
            next_state: s2,
            ok: ok,
            duration: opts[:duration].to_f,
            terminal: false
          }
          ep[:steps] << trans
          ep[:state] = s2
          ep[:last_action] = action
          trans
        rescue StandardError => e
          warn "[pwn-ai/policy] observe_step swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # report = PWN::AI::Agent::Policy.finish(
        #   session_id: 'optional - active episode id',
        #   score: 'optional - Reward.judge 0..1 (training target)',
        #   verdict: 'optional - solved|partial|wrong|refused',
        #   proxy_ok: 'optional - Boolean fallback when no judge score'
        # )

        public_class_method def self.finish(opts = {})
          return { skipped: :disabled } unless enabled?

          ep = Thread.current[EP_KEY]
          return { skipped: :no_episode } unless ep.is_a?(Hash)

          return { skipped: :session_mismatch } if opts[:session_id] && ep[:session_id] && opts[:session_id].to_s != ep[:session_id].to_s

          unless ep[:steps].empty?
            last = ep[:steps].last
            last[:next_state] = state(
              kind: ep[:kind],
              request: ep[:request],
              last_action: last[:action] || ep[:last_action],
              fails: ep[:fails],
              engine: ep[:engine],
              ts_state: opts[:ts_state],
              final: opts[:final],
              score: opts[:score]
            )
          end
          terminal = terminal_reward(score: opts[:score], proxy_ok: opts[:proxy_ok])
          if ep[:steps].empty?
            ep[:steps] << {
              state: ep[:state],
              action: 'final',
              reward: 0.0,
              next_state: ep[:state],
              ok: true,
              duration: 0.0,
              terminal: true
            }
          end
          ep[:steps].last[:reward] = (ep[:steps].last[:reward].to_f + terminal).round(4)
          ep[:steps].last[:terminal] = true
          ep[:score] = opts[:score]
          ep[:verdict] = opts[:verdict]
          ep[:return] = discounted_return(steps: ep[:steps])
          ep[:ended_at] = Time.now.utc.iso8601

          n_td = 0
          n_pg = 0
          ep[:steps].each_with_index do |tr, idx|
            n_td += 1 if update_q!(transition: tr)
            g = discounted_return(steps: ep[:steps][idx..])
            n_pg += 1 if update_pg!(state: tr[:state], action: tr[:action], advantage: g - value(state: tr[:state]))
          end

          persist_episode!(episode: ep)
          Thread.current[EP_KEY] = nil
          {
            session_id: ep[:session_id],
            steps: ep[:steps].length,
            return: ep[:return],
            score: opts[:score],
            td_updates: n_td,
            pg_updates: n_pg
          }
        rescue StandardError => e
          warn "[pwn-ai/policy] finish swallowed: #{e.class}: #{e.message}"
          Thread.current[EP_KEY] = nil
          { error: "#{e.class}: #{e.message}" }
        end

        # ----------------------------------------------------------------
        # Value-based update (Q-learning) + policy-gradient (REINFORCE)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # q = PWN::AI::Agent::Policy.update_q!(
        #   transition: 'required - Hash with :state :action :reward :next_state :terminal'
        # )

        public_class_method def self.update_q!(opts = {})
          return nil unless enabled?

          tr = opts[:transition] || opts
          s  = tr[:state].to_s
          a  = tr[:action].to_s
          return nil if s.empty? || a.empty?

          r  = tr[:reward].to_f
          s2 = tr[:next_state].to_s
          term = tr[:terminal] ? true : false
          tab = load
          qsa = read_q(table: tab, state: s, action: a)
          max_n = term ? 0.0 : max_q(table: tab, state: s2)
          target = r + (GAMMA * max_n)
          td = target - qsa
          new_q = qsa + (ALPHA * td)
          write_q!(table: tab, state: s, action: a, value: new_q)
          bump_visit!(table: tab, state: s, action: a)
          tab[:n_updates] = tab[:n_updates].to_i + 1
          tab[:td_abs_sum] = tab[:td_abs_sum].to_f + td.abs
          save(table: tab)
          new_q.round(5)
        rescue StandardError => e
          warn "[pwn-ai/policy] update_q! swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # h = PWN::AI::Agent::Policy.update_pg!(
        #   state: 'required',
        #   action: 'required',
        #   advantage: 'required - scalar G_t − V(s)'
        # )

        public_class_method def self.update_pg!(opts = {})
          return nil unless enabled?

          s = opts[:state].to_s
          a = opts[:action].to_s
          adv = opts[:advantage].to_f
          return nil if s.empty? || a.empty?
          return 0.0 if adv.abs < 1e-9

          tab = load
          logits = (tab[:h][s.to_sym] || {}).dup
          logits[a.to_sym] = logits[a.to_sym].to_f
          pi = softmax(logits: logits)
          logits.each_key do |act|
            grad = act.to_s == a ? (1.0 - pi[act].to_f) : -pi[act].to_f
            logits[act] = logits[act].to_f + (ALPHA_PG * adv * grad)
          end
          tab[:h][s.to_sym] = logits
          save(table: tab)
          logits[a.to_sym].to_f.round(5)
        rescue StandardError => e
          warn "[pwn-ai/policy] update_pg! swallowed: #{e.class}: #{e.message}"
          nil
        end

        # ----------------------------------------------------------------
        # Query — used by Registry.rank (advisory only)
        # ----------------------------------------------------------------

        public_class_method def self.q(opts = {})
          read_q(table: load, state: opts[:state], action: opts[:action])
        rescue StandardError
          0.0
        end

        public_class_method def self.value(opts = {})
          max_q(table: load, state: opts[:state])
        rescue StandardError
          0.0
        end

        # Q(s,a) − V(s). Unknown / cold-start pairs return 0 so rank is unchanged.

        public_class_method def self.advantage(opts = {})
          return 0.0 unless enabled?

          s = opts[:state] || current_state
          a = opts[:action].to_s
          return 0.0 if s.to_s.empty? || a.empty?

          tab = load
          visits = read_visit(table: tab, state: s, action: a)
          qsa = smoothed_q(table: tab, state: s, action: a)
          # Tiny visit counts stay at 0 unless the value is already decisive.
          return 0.0 if visits < VISITS_MIN && qsa.abs < 0.08

          (qsa - max_q(table: tab, state: s)).round(4)
        rescue StandardError
          0.0
        end

        # Supported Method Parameters::
        # pick = PWN::AI::Agent::Policy.recommend(
        #   state: 'optional - default current episode state',
        #   actions: 'required - Array of tool names',
        #   epsilon: 'optional - explore probability (default EPSILON)'
        # )

        public_class_method def self.recommend(opts = {})
          actions = Array(opts[:actions]).map(&:to_s).reject(&:empty?)
          return { action: nil, reason: :empty } if actions.empty?

          s = opts[:state] || current_state || 'unknown'
          eps = opts.key?(:epsilon) ? opts[:epsilon].to_f : EPSILON
          return { action: actions.sample, reason: :explore, state: s, epsilon: eps } if rand < eps

          tab = load
          scored = actions.map { |a| [a, smoothed_q(table: tab, state: s, action: a)] }
          best = scored.max_by { |_, v| v }
          { action: best[0], q: best[1].round(4), reason: :greedy, state: s, ranked: scored.sort_by { |_, v| -v } }
        rescue StandardError => e
          { action: Array(opts[:actions]).first, reason: :error, error: e.message }
        end

        public_class_method def self.current_state
          ep = Thread.current[EP_KEY]
          ep.is_a?(Hash) ? ep[:state] : nil
        end

        public_class_method def self.current_episode
          Thread.current[EP_KEY]
        end

        # Hermes split: snapshot + clear the live episode so Loop.maybe_finish_policy
        # is a no-op on the user-visible path while TurnFinalizer re-attaches it
        # on the background review thread.

        public_class_method def self.detach_episode!
          ep = Thread.current[EP_KEY]
          Thread.current[EP_KEY] = nil
          ep
        end

        public_class_method def self.attach_episode!(opts = {})
          Thread.current[EP_KEY] = opts[:episode]
          opts[:episode]
        end

        # ----------------------------------------------------------------
        # Persistence / eval
        # ----------------------------------------------------------------

        public_class_method def self.load
          FileUtils.mkdir_p(File.dirname(POLICY_FILE))
          return blank_table unless File.exist?(POLICY_FILE)

          data = JSON.parse(File.read(POLICY_FILE), symbolize_names: true)
          data[:q] = {} unless data[:q].is_a?(Hash)
          data[:h] = {} unless data[:h].is_a?(Hash)
          data[:visits] = {} unless data[:visits].is_a?(Hash)
          data[:returns] = Array(data[:returns])
          data
        rescue StandardError
          blank_table
        end

        public_class_method def self.save(opts = {})
          table = opts[:table] || load
          table[:updated_at] = Time.now.utc.iso8601
          FileUtils.mkdir_p(File.dirname(POLICY_FILE))
          path = POLICY_FILE
          tmp = File.join(File.dirname(path), ".#{File.basename(path)}.#{Process.pid}.tmp")
          File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
            f.flock(File::LOCK_EX)
            f.write(JSON.pretty_generate(table))
            f.flush
            f.fsync
          end
          File.rename(tmp, path)
          table
        ensure
          FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
        end

        public_class_method def self.trajectories(opts = {})
          limit = (opts[:limit] || 50).to_i
          return [] unless File.exist?(TRAJECTORY_FILE)

          File.readlines(TRAJECTORY_FILE).last(limit).filter_map do |line|
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            nil
          end.reverse
        rescue StandardError
          []
        end

        public_class_method def self.stats
          tab = load
          q_pairs = 0
          tab[:q].each_value { |acts| q_pairs += acts.length if acts.is_a?(Hash) }
          rets = Array(tab[:returns])
          mean_r = rets.empty? ? nil : (rets.sum.to_f / rets.length).round(4)
          n_up = tab[:n_updates].to_i
          td_mean = n_up.positive? ? (tab[:td_abs_sum].to_f / n_up).round(4) : nil
          {
            enabled: enabled?,
            n_updates: n_up,
            n_states: tab[:q].length,
            n_pairs: q_pairs,
            n_episodes: rets.length,
            mean_return: mean_r,
            mean_abs_td: td_mean,
            alpha: ALPHA,
            gamma: GAMMA,
            epsilon: EPSILON
          }
        end

        # Replay stored trajectories under the current Q table.
        # Does not write. Used by task 7 (evaluate policy quality).

        public_class_method def self.evaluate(opts = {})
          rows = trajectories(limit: opts[:limit] || 200)
          return { n: 0, mean_return: nil, greedy_match: nil, mean_abs_td: nil } if rows.empty?

          tab = load
          abs_td = []
          greedy_hits = 0
          greedy_n = 0
          rows.each do |ep|
            Array(ep[:steps]).each do |tr|
              s = tr[:state].to_s
              a = tr[:action].to_s
              next if s.empty? || a.empty?

              qsa = read_q(table: tab, state: s, action: a)
              max_n = tr[:terminal] ? 0.0 : max_q(table: tab, state: tr[:next_state])
              abs_td << (tr[:reward].to_f + (GAMMA * max_n) - qsa).abs
              acts = (tab[:q][s.to_sym] || {}).keys.map(&:to_s)
              next if acts.empty?

              greedy_n += 1
              best = acts.max_by { |act| read_q(table: tab, state: s, action: act) }
              greedy_hits += 1 if best == a
            end
          end
          rets = rows.map { |r| r[:return].to_f }
          {
            n: rows.length,
            mean_return: (rets.sum / rets.length).round(4),
            mean_abs_td: abs_td.empty? ? nil : (abs_td.sum / abs_td.length).round(4),
            greedy_match: greedy_n.positive? ? (greedy_hits.to_f / greedy_n).round(3) : nil
          }
        rescue StandardError => e
          { n: 0, error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.to_context(opts = {})
          return '' unless enabled?

          maybe_warmup! unless episode_budget_met?
          s = stats
          lines = []
          unless episode_budget_met?
            lines << 'POLICY (R5 tabular Q / REINFORCE — advisory only, does not replace planning)'
            lines << "  policy cold episodes=#{s[:n_episodes]}/#{COLD_EPISODES} — omit greedy suggestion"
            return "#{lines.join("\n")}\n"
          end

          ev = evaluate(limit: opts[:limit] || 40)
          fallback = %w[memory_recall sessions_view pwn_eval shell mistakes_record mistakes_resolve learning_note_outcome memory_remember]
          pref = begin
            PWN::AI::Agent::Registry.preference_order
          rescue StandardError
            []
          end
          actions = pref.empty? ? fallback : pref
          rec = begin
            recommend(actions: actions, epsilon: 0.0)[:action]
          rescue StandardError
            nil
          end
          lines << 'POLICY (R5 tabular Q / REINFORCE — advisory only, does not replace planning)'
          lines << "  episodes=#{s[:n_episodes]} states=#{s[:n_states]} pairs=#{s[:n_pairs]} updates=#{s[:n_updates]}"
          lines << "  mean_return=#{s[:mean_return] || '-'} mean|TD|=#{s[:mean_abs_td] || '-'} greedy_match=#{ev[:greedy_match] || '-'}"
          lines << "  current_state=#{current_state || '(none)'} suggest=#{rec || '-'} tool_preference=#{actions.join(',')}"
          "#{lines.join("\n")}\n"
        rescue StandardError
          ''
        end

        public_class_method def self.lean!(opts = {})
          dry = opts[:dry_run] ? true : false
          return { skipped: true } unless File.exist?(TRAJECTORY_FILE)

          rows = File.readlines(TRAJECTORY_FILE)
          keep = []
          rows.each do |line|
            ep = JSON.parse(line, symbolize_names: true)
            gold = ep[:return].to_f >= GOLD_MIN || ep[:score].to_f >= GOLD_MIN
            keep << [ep, line, gold]
          rescue StandardError
            next
          end
          gold = keep.select { |_, _, g| g }.map { |_, line, _| line }
          rest = keep.reject { |_, _, g| g }.last([MAX_TRAJ - gold.length, 0].max).map { |_, line, _| line }
          out = gold + rest
          unless dry
            tmp = "#{TRAJECTORY_FILE}.#{Process.pid}.tmp"
            File.write(tmp, out.join)
            File.rename(tmp, TRAJECTORY_FILE)
          end
          { removed: rows.length - out.length, remaining: out.length, dry_run: dry }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.reset
          FileUtils.rm_f(POLICY_FILE)
          FileUtils.rm_f(TRAJECTORY_FILE)
          Thread.current[EP_KEY] = nil
          blank_table
        end

        public_class_method def self.enabled?
          return true unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          v = begin
            PWN::Env.dig(:ai, :agent, :policy)
          rescue StandardError
            nil
          end
          v.nil? || !!v
        rescue StandardError
          true
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Policy.begin_episode(session_id:, request:, kind:, engine:)
              PWN::AI::Agent::Policy.observe_step(action: 'shell', ok: true, duration: 0.2)
              PWN::AI::Agent::Policy.finish(session_id:, score: 0.8, verdict: :solved)
              PWN::AI::Agent::Policy.q(state:, action:)
              PWN::AI::Agent::Policy.advantage(state:, action:)   # Registry.rank term
              PWN::AI::Agent::Policy.recommend(actions: %w[shell pwn_eval])
              PWN::AI::Agent::Policy.evaluate(limit: 100)
              PWN::AI::Agent::Policy.stats
              PWN::AI::Agent::Policy.episode_budget_met?
              PWN::AI::Agent::Policy.to_context
              PWN::AI::Agent::Policy.lean!(dry_run: true)
              PWN::AI::Agent::Policy.warmup!(limit: 200)
              PWN::AI::Agent::Policy.reset

              #{self}.authors
          USAGE
        end

        # ----------------------------------------------------------------
        private

        private_class_method def self.blank_table
          { q: {}, h: {}, visits: {}, returns: [], n_updates: 0, td_abs_sum: 0.0, updated_at: nil }
        end

        private_class_method def self.normalize_kind(opts = {})
          raw = opts[:raw].to_s.downcase
          return 'goal' if raw.empty?
          return raw if %w[statement question autonomous_goal goal howto recall greeting recon_act].include?(raw)
          return 'goal' if raw.include?('goal') || raw.include?('act')

          raw[0, 16]
        end

        private_class_method def self.task_family(opts = {})
          t = opts[:text].to_s.downcase
          return 'howto' if t.match?(/\b(how\s+to|syntax|usage|flags?)\b/)
          return 'recon' if t.match?(/\b(scan|nmap|hping|recon|sweep|osint)\b/)
          return 'code' if t.match?(/\b(rubocop|rake|rspec|fix|patch|implement|refactor)\b/)
          return 'recall' if t.match?(/\b(what did i|remind|previous turn|last request)\b/)
          return 'ops' if t.match?(/\b(cron|swarm|session|memory|skill)\b/)

          'misc'
        end

        private_class_method def self.task_bucket(opts = {})
          tokens = opts[:text].to_s.downcase.scan(/[a-z0-9_]{3,}/).first(6)
          return 0 if tokens.empty?

          Digest::SHA256.hexdigest(tokens.join('|'))[0, 8].to_i(16) % TASK_MOD
        end

        private_class_method def self.action_bucket(opts = {})
          name = opts[:name].to_s
          return 0 if name.empty? || name == 'start'

          Digest::SHA256.hexdigest(name)[0, 8].to_i(16) % ACTION_MOD
        end

        private_class_method def self.fail_bin(opts = {})
          n = opts[:count].to_i
          return 0 if n <= 0
          return 1 if n <= 2

          2
        end

        private_class_method def self.active_task_text(opts = {})
          ts = opts[:ts_state]
          if ts.is_a?(Hash) && defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:active_task)
            info = TaskSummarizer.active_task(state: ts)
            return info[:item].to_s if info.is_a?(Hash) && !info[:item].to_s.empty?
          end
          opts[:request].to_s
        rescue StandardError
          opts[:request].to_s
        end

        private_class_method def self.terminal_reward(opts = {})
          return ((2.0 * opts[:score].to_f) - 1.0).clamp(-1.0, 1.0) unless opts[:score].nil?

          distrust = 0.0
          distrust = Reward.proxy_distrust.to_f if defined?(Reward) && Reward.respond_to?(:proxy_distrust)
          # Do not train a 1.0/−1.0 terminal on the lying handler-ok proxy.
          return 0.0 if distrust >= 0.85

          opts[:proxy_ok] ? 0.25 : -0.25
        rescue StandardError
          0.0
        end

        private_class_method def self.discounted_return(opts = {})
          g = 0.0
          Array(opts[:steps]).reverse_each { |tr| g = tr[:reward].to_f + (GAMMA * g) }
          g.round(4)
        end

        private_class_method def self.read_q(opts = {})
          tab = opts[:table] || load
          s = opts[:state].to_s.to_sym
          a = opts[:action].to_s.to_sym
          ((tab[:q][s] || {})[a] || 0.0).to_f
        end

        private_class_method def self.max_q(opts = {})
          tab = opts[:table] || load
          s = opts[:state].to_s.to_sym
          acts = tab[:q][s]
          return 0.0 unless acts.is_a?(Hash) && !acts.empty?

          acts.values.map(&:to_f).max
        end

        private_class_method def self.write_q!(opts = {})
          tab = opts[:table]
          s = opts[:state].to_s.to_sym
          a = opts[:action].to_s.to_sym
          tab[:q][s] ||= {}
          tab[:q][s][a] = opts[:value].to_f.round(5)
        end

        private_class_method def self.read_visit(opts = {})
          tab = opts[:table] || load
          s = opts[:state].to_s.to_sym
          a = opts[:action].to_s.to_sym
          ((tab[:visits][s] || {})[a] || 0).to_i
        end

        private_class_method def self.bump_visit!(opts = {})
          tab = opts[:table]
          s = opts[:state].to_s.to_sym
          a = opts[:action].to_s.to_sym
          tab[:visits][s] ||= {}
          tab[:visits][s][a] = tab[:visits][s][a].to_i + 1
        end

        private_class_method def self.softmax(opts = {})
          logits = opts[:logits] || {}
          return {} if logits.empty?

          mx = logits.values.map(&:to_f).max
          exps = logits.transform_values { |v| Math.exp(v.to_f - mx) }
          z = exps.values.sum
          z = 1.0 if z <= 0.0
          exps.transform_values { |v| v / z }
        end

        private_class_method def self.plan_quality_bin(opts = {})
          ts = opts[:ts_state]
          return 'n' unless ts.is_a?(Hash)

          plan = Array(ts[:plan]).map { |t| t.to_s.strip }.reject(&:empty?)
          return 'n' if plan.empty?

          idx = ts[:plan_idx].to_i.clamp(0, plan.length)
          frac = idx.to_f / plan.length
          return 'h' if frac >= 0.75 || idx >= (plan.length - 1)
          return 'm' if frac >= 0.3

          'l'
        rescue StandardError
          'n'
        end

        private_class_method def self.completeness_bin(opts = {})
          final = opts[:final].to_s
          return 'n' if final.strip.empty?

          truncated = final.length > 80 && final.match?(/[a-z,;:]$/i) && !final.match?(/[.!?]["')\]]*\s*\z/)
          return 'l' if truncated || final.length < 80
          return 'h' if final.length >= 240 || (!opts[:score].nil? && opts[:score].to_f >= 0.75)

          'm'
        rescue StandardError
          'n'
        end

        private_class_method def self.usable_bin(opts = {})
          final = opts[:final].to_s
          score = opts[:score]
          return 'n' if final.strip.empty?
          return 'n' if defined?(Learning) && Learning.const_defined?(:FAILURE_FINAL_RX) && final.match?(Learning::FAILURE_FINAL_RX)
          return 'y' if !score.nil? && score.to_f >= 0.6
          return 'n' if !score.nil? && score.to_f < 0.4
          return 'y' if final.length >= 80 && final.match?(/[.!?]["')\]]*\s*\z/)

          'n'
        rescue StandardError
          'n'
        end

        # Neighbor average so a never-seen (s,a) is not a cold 0.0.
        private_class_method def self.smoothed_q(opts = {})
          tab = opts[:table] || load
          s = opts[:state].to_s
          a = opts[:action].to_s
          exact = read_q(table: tab, state: s, action: a)
          return exact if read_visit(table: tab, state: s, action: a).positive?

          parts = s.split('|')
          return exact if parts.length < 3

          kind = parts[0]
          task = parts[1]
          eng = parts[-1]
          act = a.to_sym
          vals = []
          tab[:q].each do |key, acts|
            next unless acts.is_a?(Hash) && acts.key?(act)

            ks = key.to_s.split('|')
            next unless ks[0] == kind && ks[1] == task && ks[-1] == eng

            vals << acts[act].to_f
          end
          return exact if vals.empty?

          (vals.sum / vals.length).round(5)
        rescue StandardError
          0.0
        end

        # Replay stored trajectories into Q so a cold table is not empty advice.
        public_class_method def self.warmup!(opts = {})
          return { skipped: :disabled } unless enabled?
          return { skipped: :no_traj } unless File.exist?(TRAJECTORY_FILE)

          tab = load
          rows = trajectories(limit: opts[:limit] || 400)
          n = 0
          2.times do
            rows.reverse_each do |ep|
              Array(ep[:steps]).each do |tr|
                s = tr[:state].to_s
                a = tr[:action].to_s
                next if s.empty? || a.empty?

                r = tr[:reward].to_f
                s2 = tr[:next_state].to_s
                term = tr[:terminal] ? true : false
                qsa = read_q(table: tab, state: s, action: a)
                max_n = term ? 0.0 : max_q(table: tab, state: s2)
                target = r + (GAMMA * max_n)
                td = target - qsa
                write_q!(table: tab, state: s, action: a, value: qsa + (ALPHA * td))
                bump_visit!(table: tab, state: s, action: a)
                tab[:n_updates] = tab[:n_updates].to_i + 1
                tab[:td_abs_sum] = tab[:td_abs_sum].to_f + td.abs
                n += 1
              end
            end
          end
          # Credit stored returns toward the episode budget so greedy
          # suggestions are not omitted after a successful replay of a
          # table that never finished COLD_EPISODES live turns.
          rets = Array(tab[:returns])
          need = COLD_EPISODES - rets.length
          if need.positive?
            extras = rows.filter_map { |ep| ep[:return] unless ep[:return].nil? }.first(need)
            tab[:returns] = (rets + extras).last(200)
          end
          tab[:warmed_at] = Time.now.utc.iso8601
          save(table: tab)
          { replayed: rows.length, td_updates: n, n_episodes: Array(load[:returns]).length }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.maybe_warmup!
          return { skipped: :disabled } unless enabled?
          return { skipped: :no_traj } unless File.exist?(TRAJECTORY_FILE)

          tab = load
          pairs = 0
          tab[:q].each_value { |acts| pairs += acts.length if acts.is_a?(Hash) }
          return { skipped: :warmed } if !tab[:warmed_at].to_s.empty? && pairs >= COLD_EPISODES && !cold?

          warmup!
        rescue StandardError
          { skipped: :error }
        end

        private_class_method def self.persist_episode!(opts = {})
          ep = opts[:episode]
          return unless ep.is_a?(Hash)

          tab = load
          tab[:returns] = (Array(tab[:returns]) + [ep[:return].to_f]).last(200)
          save(table: tab)
          FileUtils.mkdir_p(File.dirname(TRAJECTORY_FILE))
          row = {
            session_id: ep[:session_id],
            request: ep[:request],
            kind: ep[:kind],
            engine: ep[:engine],
            started_at: ep[:started_at],
            ended_at: ep[:ended_at],
            score: ep[:score],
            verdict: ep[:verdict],
            return: ep[:return],
            steps: ep[:steps]
          }
          File.open(TRAJECTORY_FILE, 'a') { |f| f.puts(JSON.dump(row)) }
        end
      end
    end
  end
end
