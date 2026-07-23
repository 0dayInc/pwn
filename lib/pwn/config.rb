# frozen_string_literal: true

require 'fileutils'
require 'yaml'

module PWN
  # Used to manage PWN configuration settings within PWN drivers.
  module Config
    # Supported Method Parameters::
    # tmpl = PWN::Config.env_template
    #
    # The canonical current-release ~/.pwn/pwn.yaml shape as a pure Hash
    # (no I/O, no vault write, no puts).  Single source of truth used by:
    #   * PWN::Config.default_env      — seed a fresh ~/.pwn/pwn.yaml
    #   * PWN::Migrate.vault_drift     — diff a user vault against this release
    #   * PWN::Migrate.backfill_vault  — deep-merge missing keys UNDER the
    #     user values on `pwn setup --migrate --fix`
    public_class_method def self.env_template
      {
        ai: {
          active: 'grok',
          module_reflection: false,
          grok: {
            base_uri: 'optional - Base URI for Grok - Use private base OR defaults to https://api.x.ai/v1',
            key: 'required - xAI Grok API Key',
            model: 'optional - Grok model to use',
            system_role_content: 'You are an ethically hacking xAI Grok agent.',
            temp: 'optional - Grok temperature',
            max_prompt_length: 256_000,
            # OAuth support for xAI SuperGrok subscriptions (in addition to API key)
            # Populate via pwn-vault command (values stored encrypted in ~/.pwn/pwn.yaml)
            oauth: {
              # xAI Grok OAuth uses a PUBLIC client (Grok-CLI, same as hermes-agent) --
              # NO client_secret. Run PWN::AI::Grok.obtain_oauth_bearer_token once
              # (RFC 8628 device flow) then store refresh_token here; PWN refreshes
              # the short-lived access_token automatically on every run.
              refresh_token: 'optional - xAI SuperGrok OAuth Refresh Token (durable; enables silent re-auth)',
              bearer_token: 'optional - xAI SuperGrok OAuth Access Token (short-lived JWT; auto-refreshed if refresh_token set)',
              client_id: 'optional - override public Grok-CLI client_id (default: b1a00492-073a-47ea-816f-4c329264a828)',
              scope: 'optional - override OAuth scope (default: openid profile email offline_access grok-cli:access api:access)',
              token_uri: 'optional - override OAuth token endpoint (default: https://auth.x.ai/oauth2/token)',
              enroll: 'optional - set true to force device-flow enrollment even when an API key is present'
            }
          },
          openai: {
            base_uri: 'optional - Base URI for OpenAI - Use private base OR defaults to https://api.openai.com/v1',
            key: 'required - OpenAI API Key',
            model: 'optional - OpenAI model to use',
            system_role_content: 'You are an ethically hacking OpenAI agent.',
            temp: 'optional - OpenAI temperature',
            max_tokens: 'optional - Max output tokens per response (default 16384). Mapped to OpenAI wire param max_completion_tokens.',
            max_prompt_length: 128_000
          },
          ollama: {
            base_uri: 'required - Base URI for Open WebUI - e.g. https://ollama.local',
            key: 'required - Open WebUI API Key Under Settings  >> Account >> JWT Token',
            model: 'required - Ollama model to use',
            embed_model: 'optional - embedding model for PWN::MemoryIndex (default nomic-embed-text)',
            system_role_content: 'You are an ethically hacking Ollama agent.',
            temp: 'optional - Ollama temperature',
            num_ctx: 32_768,
            # Cap decode length so thinking models cannot stream forever
            # (Net::HTTP read_timeout only fires on idle gaps between chunks).
            num_predict: 4_096,
            keep_alive: '30m',
            # tighten each PromptBuilder block for the local model (nil = engine defaults)
            prompt_budget: { memory: 6, metrics: 3, mistakes: 3, learning: 2, extro: false },
            # omit format:'json' when tools present unless explicitly set (see chat_with_tools)
            # format: nil,
            result_max: 4_000, # tool-result cap for local models (frontier keeps Result::DEFAULT_MAX)
            max_prompt_length: 32_000
          },
          anthropic: {
            base_uri: 'optional - Base URI for Anthropic - Use private base OR defaults to https://api.anthropic.com/v1',
            key: 'required - Anthropic API Key',
            model: 'optional - Anthropic model id to use (see provider docs for currently-supported ids)',
            system_role_content: 'You are an ethically hacking Anthropic agent.',
            temp: 'optional - Anthropic temperature',
            max_tokens: 'optional - Max output tokens per response (default 8192). Raise if tool calls truncate.',
            max_prompt_length: 200_000
          },
          gemini: {
            base_uri: 'optional - Base URI for Gemini - Use private base OR defaults to https://generativelanguage.googleapis.com/v1beta',
            key: 'required - Google Gemini API Key',
            model: 'optional - Gemini model id to use (see provider docs for currently-supported ids)',
            system_role_content: 'You are an ethically hacking Gemini agent.',
            temp: 'optional - Gemini temperature',
            max_prompt_length: 1_000_000
          },
          # teacher-student reflection: execute on :active, write durable lessons via this engine (nil = same as :active)
          reflect_engine: nil,
          # optional model override on :reflect_engine (nil = engine default)
          reflect_model: nil,
          agent: {
            native_tools: true,
            max_iters: 25, # live override 80 is frontier leakage; ollama should stay ≤25
            # Swarm (agent_ask/agent_debate) sub-agent recursion cap
            max_depth: 3,
            # run PWN::AI::Agent::Learning.auto_introspect after every final answer
            auto_introspect: true,
            # also run PWN::AI::Agent::Extrospection.auto_extrospect from auto_introspect
            # (host/repo/env probes only — no toolchain/GUI/net side-effects)
            auto_extrospect: true,
            # engine-agnostic scaffolding (defaults tuned for local models)
            plan_first: nil,               # nil = auto (true when :active == :ollama)
            tool_router: nil,              # nil = auto (true when :active == :ollama) — cuts ~11k→~3k schema tokens
            escalation_persona: 'escalator', # Swarm persona for frontier corrective hints when a local model is stuck
            # sample E3 verify_as_reward: true|false|nil(auto: ~10% local / always frontier when CLAIM_RX hits)
            verify_as_reward: nil,
            # end-of-turn auto_introspect policy for local: :always | :failure_only | :every_n (with introspect_every_n)
            local_introspect: :failure_only,
            introspect_every_n: 3,
            # history compaction keep last K tool pairs + plan (chars budget for ollama)
            history_keep_tool_pairs: 6,
            history_tool_max_chars: 2_000,
            toolsets: nil
            # multi-agent personas : ~/.pwn/agents.yml  (see PWN::AI::Agent::Swarm.help)
            # swarm bus            : ~/.pwn/swarm/<swarm_id>/bus.jsonl
          }
        },
        plugins: {
          asm: { arch: PWN::Plugins::DetectOS.arch, endian: PWN::Plugins::DetectOS.endian.to_s },
          blockchain: {
            bitcoin: {
              rpc_host: 'localhost',
              rpc_port: 8332,
              rpc_user: 'bitcoin RPC Username',
              rpc_pass: 'bitcoin RPC Password'
            }
          },
          hunter: { api_key: 'hunter.how API Key' },
          jira_data_center: {
            base_uri: 'Jira Server Base API URI (e.g. https://jira.company.com/rest/api/latest)',
            token: 'Jira Server API Token'
          },
          meshtastic: {
            admin_key: 'Public key authorized to send admin messages to nodes',
            serial: {
              port: '/dev/ttyUSB0',
              baud: 115_200,
              bits: 8,
              stop: 1,
              parity: :none
            },
            mqtt: {
              host: 'mqtt.meshtastic.org',
              port: 1883,
              tls: false,
              user: 'meshdev',
              pass: 'large4cats'
            },
            channel: {
              active: 'LongFast',
              LongFast: {
                psk: 'AQ==',
                region: 'US/<STATE>',
                topic: '2/e/#',
                channel_num: 8
              },
              PWN: {
                psk: 'required - PSK for pwn channel',
                region: 'US/<STATE>',
                topic: '2/e/PWN/#',
                channel_num: 99
              }
            }
          },
          shodan: { api_key: 'SHODAN API Key' }
        },
        memory: {
          enabled: true,
          provider: 'file' # file | sqlite (future)
        },
        sessions: {
          enabled: true,
          provider: 'jsonl'
        },
        cron: {
          enabled: true,
          provider: 'yaml'
        }
      }
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # env = PWN::Config.default_env(
    #   pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml'
    # )
    public_class_method def self.default_env(opts = {})
      pwn_env_path = opts[:pwn_env_path]
      pwn_dec_path = "#{pwn_env_path}.decryptor"

      puts "
        [*] NOTICE:
        1. Writing minimal PWN::Env to:
           #{pwn_env_path}
        2. Your decryptor file will be written to:
           #{pwn_dec_path}
        3. Use the pwn-vault command in the pwn prototyping driver to update:
           #{pwn_env_path}
        4. For optimal security, it's recommended to move:
           #{pwn_dec_path}
           to a secure location and use the --pwn-dec parameter for PWN drivers.
      "
      env = env_template

      # Remove beginning colon from key names

      yaml_env = YAML.dump(env).gsub(/^(\s*):/, '\1')
      File.write(pwn_env_path, yaml_env)
      # Change file permission to 600
      File.chmod(0o600, pwn_env_path)

      # Ensure skills dir for pwn-ai agent (in parent of pwn_env_path)
      pwn_env_root = File.dirname(pwn_env_path)
      pwn_skills_path = File.join(pwn_env_root, 'skills')
      FileUtils.mkdir_p(pwn_skills_path)

      env[:driver_opts] = {
        pwn_env_path: pwn_env_path,
        pwn_dec_path: pwn_dec_path
      }

      PWN::Plugins::Vault.create(
        file: pwn_env_path,
        decryptor_file: pwn_dec_path
      )

      Pry.config.refresh_pwn_env = false if defined?(Pry)
      env[:pwn_skills_path] = pwn_skills_path
      PWN::Config.load_skills(pwn_skills_path: pwn_skills_path)

      # pwn-ai agent: memory/sessions/cron paths
      env[:pwn_memory_path] = PWN::Memory::MEMORY_FILE if defined?(PWN::Memory)
      env[:pwn_sessions_path] = PWN::Sessions.sessions_dir if defined?(PWN::Sessions)
      env[:pwn_cron_path] = PWN::Cron.cron_dir if defined?(PWN::Cron)
      PWN::Cron.install_defaults if defined?(PWN::Cron) && PWN::Cron.respond_to?(:install_defaults)

      PWN.send(:remove_const, :Env) if PWN.const_defined?(:Env)

      PWN.const_set(:Env, env.freeze)
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Config.redact_sensitive_artifacts(
    #   config: 'optional - Hash to redact sensitive artifacts from.  Defaults to PWN::Env'
    # )
    public_class_method def self.redact_sensitive_artifacts(opts = {})
      config = opts[:config] ||= PWN::Env

      sensitive_keys = %i[
        admin_key
        api_key
        auth_client_secret
        bearer_token
        client_secret
        consumer_key
        key
        pass
        password
        psk
        refresh_token
        secret_key
        token
      ]

      # Transform values at the current level: redact sensitive keys
      config.transform_values.with_index do |v, k|
        if sensitive_keys.include?(config.keys[k])
          '>>> REDACTED >>> USE `pwn-vault` FOR ADMINISTRATION <<< REDACTED <<<'
        else
          v.is_a?(Hash) ? redact_sensitive_artifacts(config: v) : v
        end
      end
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # env = PWN::Config.init_driver_options
    public_class_method def self.init_driver_options
      env = {
        driver_opts: {
          pwn_env_path: nil,
          pwn_dec_path: nil
        }
      }
      PWN.const_set(:Env, env)
      # puts '[*] Loaded driver options.'
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Config.refresh_env(
    #   pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
    #   pwn_dec_path: 'optional - Path to pwn.yaml.decryptor file.  Defaults to ~/.pwn/pwn.yaml.decryptor'
    # )

    # Deep-fill missing Hash keys from defaults into target (mutates target).
    # Existing keys (including explicit false/nil) are preserved — only
    # ABSENT keys are filled. Arrays and scalars on either side are left alone.
    private_class_method def self.deep_fill!(opts = {})
      target = opts[:target]
      defaults = opts[:defaults]
      return target unless target.is_a?(Hash) && defaults.is_a?(Hash)

      defaults.each do |k, v|
        if !target.key?(k)
          target[k] = v.is_a?(Hash) ? deep_fill!(target: {}, defaults: v) : v
        elsif target[k].is_a?(Hash) && v.is_a?(Hash)
          deep_fill!(target: target[k], defaults: v)
        end
      end
      target
    end

    # Inject Ollama/RL scaffolding defaults into a vault-loaded env hash
    # before freeze. Never overwrites operator choices already in the vault.
    private_class_method def self.merge_ai_defaults!(opts = {})
      env = opts[:env]
      return env unless env.is_a?(Hash) && env[:ai].is_a?(Hash)

      # Pull the in-code default template without writing a file.
      template = {
        ollama: {
          result_max: 4_000
        },
        agent: {
          max_iters: 25,
          tool_router: nil,
          escalation_persona: 'escalator',
          verify_as_reward: nil,
          local_introspect: :failure_only,
          introspect_every_n: 3,
          history_keep_tool_pairs: 6,
          history_tool_max_chars: 2_000
        }
      }
      env[:ai][:ollama] = {} unless env[:ai][:ollama].is_a?(Hash)
      env[:ai][:agent]  = {} unless env[:ai][:agent].is_a?(Hash)
      deep_fill!(target: env[:ai][:ollama], defaults: template[:ollama])
      deep_fill!(target: env[:ai][:agent], defaults: template[:agent])
      env
    rescue StandardError => e
      warn "[pwn/config] merge_ai_defaults! swallowed: #{e.class}: #{e.message}"
      env
    end

    public_class_method def self.refresh_env(opts = {})
      pwn_env_root = "#{Dir.home}/.pwn"
      pwn_env_path = opts[:pwn_env_path] ||= "#{pwn_env_root}/pwn.yaml"
      pwn_env_root = File.dirname(pwn_env_path)
      FileUtils.mkdir_p(pwn_env_root)

      pwn_skills_path = File.join(pwn_env_root, 'skills')
      FileUtils.mkdir_p(pwn_skills_path)

      return default_env(pwn_env_path: pwn_env_path) unless File.exist?(pwn_env_path)

      is_encrypted = PWN::Plugins::Vault.file_encrypted?(file: pwn_env_path)
      raise "PWN Environment (#{pwn_env_path}) is not encrypted!  Use PWN::Vault.create(file: '#{pwn_env_path}', decryptor_file: '#{pwn_env_path}.decryptor') to encrypt it." unless is_encrypted

      pwn_dec_path = opts[:pwn_dec_path] ||= "#{pwn_env_path}.decryptor"
      raise "PWN Decryptor (#{pwn_dec_path}) does not exist!" unless File.exist?(pwn_dec_path)

      pwn_decryptor = YAML.load_file(pwn_dec_path, symbolize_names: true)

      key = opts[:key] ||= pwn_decryptor[:key] ||= ENV.fetch('PWN_DECRYPTOR_KEY')
      key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption Key') if key.nil?

      iv = opts[:iv] ||= pwn_decryptor[:iv] ||= ENV.fetch('PWN_DECRYPTOR_IV')
      iv = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption IV') if iv.nil?

      env = PWN::Plugins::Vault.dump(
        file: pwn_env_path,
        key: key,
        iv: iv
      )

      valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :agent }.map(&:downcase)

      engine = env[:ai][:active].to_s.downcase.to_sym
      raise "ERROR: Unsupported AI Engine: #{engine} in #{pwn_env_path}.  Supported AI Engines:\n#{valid_ai_engines.inspect}" unless valid_ai_engines.include?(engine)

      # Determine whether the active engine already has usable auth
      # material so the pwn / pwn-ai REPL driver does not prompt for an
      # API key when OAuth is configured via pwn-vault.
      #
      # A value is considered "real" when it is non-blank AND is not one
      # of the placeholder strings ("optional - ..." / "required - ...")
      # written by PWN::Config.default_env into a fresh ~/.pwn/pwn.yaml.
      real_cfg = lambda do |v|
        s = v.to_s.strip
        !s.empty? && !s.match?(/\A(optional|required)\b/i)
      end

      key = env[:ai][engine][:key]
      key = nil unless real_cfg.call(key)

      oauth_configured = false
      if engine == :grok
        oauth = env[:ai][engine][:oauth]
        oauth = env[:ai][engine][:oauth] = {} unless oauth.is_a?(Hash)
        # OAuth is considered configured when either a bearer_token is
        # stored (preferred, long-lived) OR client_id + client_secret are
        # present (PWN::AI::Grok will run the singular enrollment flow).
        oauth_configured = real_cfg.call(oauth[:bearer_token]) ||
                           (real_cfg.call(oauth[:client_id]) && real_cfg.call(oauth[:client_secret]))
      end

      # Never block a non-interactive process (backticks, CI, `pwn setup`
      # under rvmsudo, headless -A) waiting on a TTY::Prompt read — only
      # solicit an API key when BOTH stdin and stdout are terminals. Set
      # PWN_NONINTERACTIVE=1 to force-skip even on a real TTY.
      interactive = $stdin.tty? && $stdout.tty? && ENV['PWN_NONINTERACTIVE'].to_s.empty?

      if key.nil? && !oauth_configured && interactive
        key = PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: "#{engine} API Key (or store ai.grok.oauth.refresh_token via pwn-vault -- run PWN::AI::Grok.obtain_oauth_bearer_token to enroll)"
        )
        env[:ai][engine][:key] = key
      end

      model = env[:ai][engine][:model]
      system_role_content = env[:ai][engine][:system_role_content]

      # Reset the ai response history on env refresh
      env[:ai][engine][:response_history] = {
        id: '',
        object: '',
        model: model,
        usage: {},
        choices: [
          {
            role: 'system',
            content: system_role_content
          }
        ]
      }

      # These two lines should be immutable for the session
      env[:driver_opts] = {
        pwn_env_path: pwn_env_path,
        pwn_dec_path: pwn_dec_path
      }

      # Make pwn-ai aware of the skills folder in pwn_env parent (before freeze)
      env[:pwn_skills_path] = pwn_skills_path if defined?(pwn_skills_path)
      PWN::Config.load_skills(pwn_skills_path: pwn_skills_path) if defined?(pwn_skills_path)

      # pwn-ai agent: memory, sessions, cron paths (before freeze)
      env[:pwn_memory_path] = PWN::Memory::MEMORY_FILE if defined?(PWN::Memory)
      PWN::Memory.load if defined?(PWN::Memory)
      env[:pwn_sessions_path] = PWN::Sessions.sessions_dir if defined?(PWN::Sessions)
      env[:pwn_cron_path] = PWN::Cron.cron_dir if defined?(PWN::Cron)
      PWN::Cron.install_defaults if defined?(PWN::Cron) && PWN::Cron.respond_to?(:install_defaults)

      # Fill missing ai.agent / ai.ollama knobs from code defaults so older
      # vault files pick up Ollama/RL fixes (tool_router nil-auto, local
      # introspect policy, history compaction, result_max, escalation
      # default) without requiring a full pwn-vault rewrite. Explicit
      # vault values always win — deep_merge only supplies ABSENT keys.
      merge_ai_defaults!(env: env)

      # Assign the refreshed env to PWN::Env

      PWN.send(:remove_const, :Env) if PWN.const_defined?(:Env)
      PWN.const_set(:Env, env.freeze)

      # Redact sensitive artifacts from PWN::Env and store in PWN::EnvRedacted

      env_redacted = redact_sensitive_artifacts(config: env)
      PWN.send(:remove_const, :EnvRedacted) if PWN.const_defined?(:EnvRedacted)
      PWN.const_set(:EnvRedacted, env_redacted.freeze)

      Pry.config.refresh_pwn_env = false if defined?(Pry)

      puts "[*] PWN::Env loaded via: #{pwn_env_path}\n"

      # Upgrade drift — cheap schema-stamp check only (no per-file probes).
      if defined?(PWN::Migrate) && PWN::Migrate.needed?
        puts "[!] ~/.pwn state predates pwn #{PWN::VERSION} (schema " \
             "#{PWN::Migrate.installed_schema} < #{PWN::Migrate::SCHEMA_VERSION}). " \
             'Run `pwn setup --migrate --fix` to autofix (backup taken first).'
      end
    rescue StandardError => e
      raise e
    end

    # ──────────────────────────────────────────────────────────────────────
    #  SKILLS  (agentskills.io/specification conformant, with legacy shim)
    # ──────────────────────────────────────────────────────────────────────
    #
    # On-disk layout (spec):
    #   ~/.pwn/skills/<name>/SKILL.md      ← required entrypoint, YAML frontmatter
    #   ~/.pwn/skills/<name>/scripts/      ← optional executables (was flat *.rb)
    #   ~/.pwn/skills/<name>/references/   ← optional supporting docs
    #   ~/.pwn/skills/<name>/assets/       ← optional binary assets
    #
    # Legacy shim (read-only, still loaded so nothing breaks on upgrade):
    #   ~/.pwn/skills/<name>.{md,txt,rb,skill,yml,yaml}
    #
    # Frontmatter (SKILL.md, `---` YAML block at top of file):
    #   name:         REQUIRED  [a-z0-9-]{1,64}, must equal parent dir name
    #   description:  REQUIRED  1..1024 chars
    #   license:      optional
    #   metadata:     optional  Hash (pwn stores references here too)
    #   allowed-tools: optional Array of toolset names
    # ──────────────────────────────────────────────────────────────────────

    SKILL_ENTRY = 'SKILL.md'
    SKILL_NAME_RE = /\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\z/

    # Supported Method Parameters::
    # pwn_skills_path = PWN::Config.pwn_skills_path(
    #   pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml'
    # )
    public_class_method def self.pwn_skills_path(opts = {})
      pwn_env_path = opts[:pwn_env_path] ||= "#{Dir.home}/.pwn/pwn.yaml"
      File.join(File.dirname(pwn_env_path), 'skills')
    end

    # Supported Method Parameters::
    # name = PWN::Config.sanitize_skill_name(name: 'My Cool Skill!')
    #
    # Coerce to an agentskills.io-valid identifier:
    #   downcase → non [a-z0-9] → '-' → squeeze '-' → strip edge '-' → cap 64.
    # Raises ArgumentError when the result is empty.
    public_class_method def self.sanitize_skill_name(opts = {})
      n = opts[:name].to_s.downcase
                     .gsub(/[^a-z0-9-]+/, '-')
                     .gsub(/-{2,}/, '-')
                     .gsub(/\A-+|-+\z/, '')[0, 64]
                     .to_s
                     .gsub(/-+\z/, '') # re-strip in case truncation left a trailing '-'
      raise ArgumentError, "skill name #{opts[:name].inspect} sanitises to empty" if n.empty?
      raise ArgumentError, "skill name #{n.inspect} !~ #{SKILL_NAME_RE.inspect}" unless n.match?(SKILL_NAME_RE)

      n
    end

    # Supported Method Parameters::
    # fm = PWN::Config.parse_skill_frontmatter(content: '...')
    #
    # → { frontmatter: Hash(String keys), body: String }
    # Missing / malformed frontmatter returns { frontmatter: {}, body: content }.
    public_class_method def self.parse_skill_frontmatter(opts = {})
      content = opts[:content].to_s
      return { frontmatter: {}, body: content } unless content.start_with?("---\n")

      fm_end = content.index(/^---\s*$/, 4)
      return { frontmatter: {}, body: content } unless fm_end

      require 'yaml'
      raw = content[4...fm_end]
      fm  = YAML.safe_load(raw, permitted_classes: [Symbol, Date, Time], aliases: true) || {}
      fm  = {} unless fm.is_a?(Hash)
      body = content[fm_end..].to_s.sub(/\A---\s*\n?/, '')
      { frontmatter: fm, body: body }
    rescue StandardError
      { frontmatter: {}, body: content }
    end

    # Supported Method Parameters::
    # refs = PWN::Config.parse_skill_references(content: '...')
    #
    # Extracts an Array of reference strings (URLs, CWE/CVE/ATT&CK ids, etc.)
    # from a skill body. Supports three sources, merged & uniq'd:
    #   1) frontmatter `references:` (legacy pwn)
    #   2) frontmatter `metadata: { references: [...] }` (spec-conformant slot)
    #   3) markdown `## References` bullet section
    public_class_method def self.parse_skill_references(opts = {})
      content = opts[:content].to_s
      parsed  = parse_skill_frontmatter(content: content)
      fm      = parsed[:frontmatter]
      refs    = []

      refs.concat(Array(fm['references'] || fm[:references]).map(&:to_s))
      md = fm['metadata'] || fm[:metadata]
      refs.concat(Array(md['references'] || md[:references]).map(&:to_s)) if md.is_a?(Hash)

      if content =~ /^\s*\#{1,3}\s*References\s*$/i
        in_section = false
        content.each_line do |line|
          if line =~ /^\s*\#{1,3}\s*References\s*$/i
            in_section = true
            next
          end
          next unless in_section
          break if line =~ /^\s*\#{1,3}\s+\S/

          l = line.strip.sub(/^[-*]\s*/, '')
          refs << l unless l.empty?
        end
      end

      refs.map(&:strip).reject(&:empty?).uniq
    rescue StandardError
      []
    end

    # Supported Method Parameters::
    # out = PWN::Config.write_skill(
    #   name:        'required - free-form; sanitised to [a-z0-9-]',
    #   content:     'required - markdown body (WITHOUT frontmatter)',
    #   description: 'optional - 1..1024 chars; derived from body when omitted',
    #   references:  'optional - Array of URLs / CWE / CVE / ATT&CK / NIST ids',
    #   license:     'optional - SPDX id or free text',
    #   metadata:    'optional - Hash of arbitrary metadata',
    #   allowed_tools:   'optional - Array of toolset names',
    #   pwn_skills_path: 'optional - override skills root'
    # )
    #
    # The single agentskills.io-conformant writer used by skill_create,
    # learning_distill_skill and migrate_legacy_skills. Always writes
    # <root>/<name>/SKILL.md with required name+description frontmatter.
    public_class_method def self.write_skill(opts = {})
      root = opts[:pwn_skills_path] || pwn_skills_path
      name = sanitize_skill_name(name: opts[:name])
      body = opts[:content].to_s
      raise ArgumentError, 'content is required' if body.strip.empty?

      # If caller handed us a body that already has frontmatter, strip &
      # merge it so we never emit doubled `---` blocks.
      parsed = parse_skill_frontmatter(content: body)
      body   = parsed[:body].to_s.sub(/\A\n+/, '')
      merged = parsed[:frontmatter]

      desc = (opts[:description] || merged['description'] || merged[:description]).to_s.strip
      if desc.empty?
        first = body.lines.reject { |l| l.strip.empty? || l.strip.start_with?('#') }.first.to_s.strip
        first = body.lines.first.to_s.strip.sub(/^#+\s*/, '') if first.empty?
        desc  = first[0, 1024]
      end
      desc = desc[0, 1024]
      raise ArgumentError, 'description could not be derived (empty body?)' if desc.empty?

      refs  = (Array(opts[:references]) + Array(merged['references']) + Array(merged[:references]))
              .map(&:to_s).map(&:strip).reject(&:empty?).uniq
      meta  = merged['metadata'] || merged[:metadata] || {}
      meta  = {} unless meta.is_a?(Hash)
      meta  = meta.merge(opts[:metadata]) if opts[:metadata].is_a?(Hash)
      meta['references'] = refs unless refs.empty?

      fm = { 'name' => name, 'description' => desc }
      fm['license']       = opts[:license].to_s                       if opts[:license]
      fm['allowed-tools'] = Array(opts[:allowed_tools]).map(&:to_s)   if opts[:allowed_tools]
      fm['metadata']      = meta                                      unless meta.empty?

      require 'yaml'
      frontmatter = YAML.dump(fm).sub(/\A---\n/, '') # YAML.dump already emits leading ---
      out = "---\n#{frontmatter}---\n\n#{body.rstrip}\n"
      out << "\n## References\n#{refs.map { |r| "- #{r}" }.join("\n")}\n" if refs.any? && body !~ /^\#{1,3}\s*References\s*$/i

      dir  = File.join(root, name)
      path = File.join(dir, SKILL_ENTRY)
      FileUtils.mkdir_p(dir)
      File.write(path, out)

      { name: name, dir: dir, path: path, bytes: out.bytesize, description: desc, references: refs, format: :agentskills }
    end

    # Supported Method Parameters::
    # report = PWN::Config.migrate_legacy_skills(
    #   pwn_skills_path: 'optional - override skills root',
    #   delete_legacy:   'optional - remove flat file after migration (default true)'
    # )
    #
    # One-shot converter: every flat ~/.pwn/skills/*.md (etc.) becomes a
    # spec-conformant <name>/SKILL.md with backfilled frontmatter. Idempotent.
    public_class_method def self.migrate_legacy_skills(opts = {})
      root = opts[:pwn_skills_path] || pwn_skills_path
      del  = opts.fetch(:delete_legacy, true)
      migrated = []
      Dir.glob(File.join(root, '*.{rb,md,txt,skill,yml,yaml}')).each do |legacy|
        content = File.read(legacy)
        base    = File.basename(legacy, '.*')
        out     = write_skill(name: base, content: content, pwn_skills_path: root)
        if File.extname(legacy) == '.rb'
          FileUtils.mkdir_p(File.join(out[:dir], 'scripts'))
          FileUtils.cp(legacy, File.join(out[:dir], 'scripts', File.basename(legacy)))
        end
        FileUtils.rm_f(legacy) if del
        migrated << { from: legacy, to: out[:path] }
      rescue StandardError => e
        migrated << { from: legacy, error: e.message }
      end
      load_skills(pwn_skills_path: root)
      { migrated: migrated.length, details: migrated }
    end

    # Supported Method Parameters::
    # skills = PWN::Config.load_skills(
    #   pwn_skills_path: 'optional - Path to skills folder.  Defaults to ~/.pwn/skills'
    # )
    #
    # Loads skills into the PWN::Skills constant. Two on-disk shapes are
    # accepted so upgrades are seamless:
    #
    #   agentskills.io  →  <root>/<name>/SKILL.md      (preferred; written by write_skill)
    #   legacy flat     →  <root>/<name>.{md,txt,rb,skill,yml,yaml}
    #
    # Each entry: { type:, format:, path:, dir:, content:, description:,
    #               references:, frontmatter:, loaded:?, error:? }
    public_class_method def self.load_skills(opts = {})
      pwn_skills_path = opts[:pwn_skills_path] || (PWN.const_defined?(:Env) && PWN::Env.is_a?(Hash) && PWN::Env[:pwn_skills_path]) || self.pwn_skills_path
      FileUtils.mkdir_p(pwn_skills_path) if pwn_skills_path && !Dir.exist?(pwn_skills_path.to_s)

      skills = {}
      return skills unless pwn_skills_path && Dir.exist?(pwn_skills_path.to_s)

      # ── agentskills.io directory layout ───────────────────────────────
      Dir.glob(File.join(pwn_skills_path, '*', SKILL_ENTRY)).each do |entry|
        dir     = File.dirname(entry)
        key     = File.basename(dir).to_sym
        content = File.read(entry)
        parsed  = parse_skill_frontmatter(content: content)
        fm      = parsed[:frontmatter]
        desc    = (fm['description'] || fm[:description]).to_s.strip
        desc    = parsed[:body].to_s.lines.first.to_s.strip.sub(/^#+\s*/, '')[0, 200] if desc.empty?
        scripts = Dir.glob(File.join(dir, 'scripts', '*.rb'))

        meta = {
          type: scripts.any? ? :ruby : :instruction,
          format: :agentskills,
          path: entry,
          dir: dir,
          content: content,
          description: desc,
          frontmatter: fm,
          references: parse_skill_references(content: content),
          allowed_tools: Array(fm['allowed-tools'] || fm[:'allowed-tools'] || fm['allowed_tools'])
        }

        scripts.each do |rb|
          require rb
        rescue StandardError => e
          meta[:loaded] = false
          meta[:error]  = e.message
        end
        meta[:loaded] = true unless meta.key?(:loaded) || scripts.empty?

        skills[key] = meta
      end

      # ── legacy flat files (backward-compat shim) ──────────────────────
      Dir.glob(File.join(pwn_skills_path, '*.{rb,md,txt,skill,yml,yaml}')).each do |skill_file|
        key = File.basename(skill_file, '.*').to_sym
        next if skills.key?(key) # directory format wins on collision

        content = File.read(skill_file)
        ext     = File.extname(skill_file).downcase
        parsed  = parse_skill_frontmatter(content: content)
        desc    = parsed[:body].to_s.lines.reject { |l| l.strip.empty? || l.strip.start_with?('#', '---') }.first.to_s.strip
        desc    = parsed[:body].to_s.lines.first.to_s.strip.sub(/^#+\s*/, '')[0, 200] if desc.empty?

        base = {
          format: :legacy,
          path: skill_file,
          dir: pwn_skills_path,
          content: content,
          description: desc,
          frontmatter: parsed[:frontmatter],
          references: parse_skill_references(content: content)
        }

        if ext == '.rb'
          begin
            require skill_file
            skills[key] = base.merge(type: :ruby, loaded: true)
          rescue StandardError => e
            skills[key] = base.merge(type: :ruby, loaded: false, error: e.message)
          end
        else
          skills[key] = base.merge(type: :instruction)
        end
      end

      PWN.send(:remove_const, :Skills) if PWN.const_defined?(:Skills)
      PWN.const_set(:Skills, skills.freeze)
      skills
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    #   path = PWN::Config.pwn_memory_path
    public_class_method def self.pwn_memory_path
      defined?(PWN::Memory) ? PWN::Memory::MEMORY_FILE : File.join(Dir.home, '.pwn', 'memory.json')
    end

    # Supported Method Parameters::
    #   PWN::Config.load_memory
    public_class_method def self.load_memory
      defined?(PWN::Memory) ? PWN::Memory.load : {}
    end

    # Supported Method Parameters::
    #   path = PWN::Config.pwn_sessions_path
    public_class_method def self.pwn_sessions_path
      defined?(PWN::Sessions) ? PWN::Sessions.sessions_dir : File.join(Dir.home, '.pwn', 'sessions')
    end

    # Supported Method Parameters::
    #   path = PWN::Config.pwn_cron_path
    public_class_method def self.pwn_cron_path
      defined?(PWN::Cron) ? PWN::Cron.cron_dir : File.join(Dir.home, '.pwn', 'cron')
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):
        0day Inc. <support@0dayinc.com>
      "
    end

    # Display Usage for this Module

    public_class_method def self.help
      puts "USAGE:
        #{self}.default_env(
          pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml'
        )

        #{self}.redact_sensitive_artifacts(
          config: 'optional - Hash to redact sensitive artifacts from.  Defaults to PWN::Env'
        )

        #{self}.pwn_skills_path

        #{self}.sanitize_skill_name(name: '...')

        #{self}.write_skill(
          name: 'required', content: 'required',
          description: 'optional', references: 'optional Array',
          license: 'optional', metadata: 'optional Hash',
          allowed_tools: 'optional Array', pwn_skills_path: 'optional'
        )

        #{self}.load_skills(pwn_skills_path: 'optional')

        #{self}.migrate_legacy_skills(pwn_skills_path: 'optional', delete_legacy: true)

        #{self}.refresh_env(
          pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
        pwn_dec_path: 'optional - Path to pwn.yaml.decryptor file.  Defaults to ~/.pwn/pwn.yaml.decryptor'
        )

        #{self}.authors
      "
    end
  end
end
