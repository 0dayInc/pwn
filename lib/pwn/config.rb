# frozen_string_literal: true

require 'fileutils'
require 'yaml'

module PWN
  # Used to manage PWN configuration settings within PWN drivers.
  module Config
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
      env = {
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
            system_role_content: 'You are an ethically hacking Ollama agent.',
            temp: 'optional - Ollama temperature',
            max_prompt_length: 32_000
          },
          anthropic: {
            base_uri: 'optional - Base URI for Anthropic - Use private base OR defaults to https://api.anthropic.com/v1',
            key: 'required - Anthropic API Key',
            model: 'optional - Anthropic model to use (e.g. claude-3-5-sonnet-20240620)',
            system_role_content: 'You are an ethically hacking Anthropic agent.',
            temp: 'optional - Anthropic temperature',
            max_tokens: 'optional - Max output tokens per response (default 8192). Raise if tool calls truncate.',
            max_prompt_length: 200_000
          },
          gemini: {
            base_uri: 'optional - Base URI for Gemini - Use private base OR defaults to https://generativelanguage.googleapis.com/v1beta',
            key: 'required - Google Gemini API Key',
            model: 'optional - Gemini model to use (e.g. gemini-2.5-pro, gemini-2.5-flash)',
            system_role_content: 'You are an ethically hacking Gemini agent.',
            temp: 'optional - Gemini temperature',
            max_prompt_length: 1_000_000
          },
          agent: {
            native_tools: true,
            max_iters: 25,
            # Swarm (agent_ask/agent_debate) sub-agent recursion cap
            max_depth: 3,
            # run PWN::AI::Agent::Learning.auto_introspect after every final answer
            auto_introspect: true,
            # also run PWN::AI::Agent::Extrospection.auto_extrospect from auto_introspect
            auto_extrospect: false,
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

      if key.nil? && !oauth_configured
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

      # Assign the refreshed env to PWN::Env

      PWN.send(:remove_const, :Env) if PWN.const_defined?(:Env)
      PWN.const_set(:Env, env.freeze)

      # Redact sensitive artifacts from PWN::Env and store in PWN::EnvRedacted

      env_redacted = redact_sensitive_artifacts(config: env)
      PWN.send(:remove_const, :EnvRedacted) if PWN.const_defined?(:EnvRedacted)
      PWN.const_set(:EnvRedacted, env_redacted.freeze)

      Pry.config.refresh_pwn_env = false if defined?(Pry)

      puts "[*] PWN::Env loaded via: #{pwn_env_path}\n"
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # pwn_skills_path = PWN::Config.pwn_skills_path(
    #   pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml'
    # )
    public_class_method def self.pwn_skills_path(opts = {})
      pwn_env_path = opts[:pwn_env_path] ||= "#{Dir.home}/.pwn/pwn.yaml"
      File.join(File.dirname(pwn_env_path), 'skills')
    end

    # Supported Method Parameters::
    # refs = PWN::Config.parse_skill_references(content: '...')
    #
    # Extracts an Array of reference strings (URLs, CWE/CVE/ATT&CK ids, etc.)
    # from a skill body. Supports two formats:
    #   1) YAML front-matter block:  ---\nreferences:\n  - https://...\n---\n
    #   2) Markdown section:         ## References\n- https://...\n
    public_class_method def self.parse_skill_references(opts = {})
      content = opts[:content].to_s
      refs = []

      # YAML front-matter (--- ... ---) at top of file
      if content.start_with?("---\n")
        fm_end = content.index("\n---", 4)
        if fm_end
          begin
            require 'yaml'
            fm = YAML.safe_load(content[4..fm_end], permitted_classes: [], aliases: false) || {}
            r  = fm['references'] || fm[:references]
            refs.concat(Array(r).map(&:to_s)) if r
          rescue StandardError
            # ignore malformed front-matter
          end
        end
      end

      # Markdown "## References" section (bullets or bare lines until next heading / EOF)
      if content =~ /^\s*\#{1,3}\s*References\s*$/i
        in_section = false
        content.each_line do |line|
          if line =~ /^\s*\#{1,3}\s*References\s*$/i
            in_section = true
            next
          end
          next unless in_section
          break if line =~ /^\s*\#{1,3}\s+\S/ # next heading

          l = line.strip.sub(/^[-*]\s*/, '')
          refs << l unless l.empty?
        end
      end

      refs.map(&:strip).reject(&:empty?).uniq
    rescue StandardError
      []
    end

    # Supported Method Parameters::
    # skills = PWN::Config.load_skills(
    #   pwn_skills_path: 'optional - Path to skills folder.  Defaults to ~/.pwn/skills'
    # )
    #
    # Loads instruction-based skills (.md, .txt, .skill, .yaml) and executable Ruby skills (.rb)
    # into PWN::Skills constant (hash of basename => {type, path, content, loaded?}).
    # The pwn-ai command (REPL driver) loads and is aware of this folder to expand
    # autonomous agent capabilities (skill documents loaded for task execution).
    public_class_method def self.load_skills(opts = {})
      pwn_skills_path = opts[:pwn_skills_path] || PWN::Env[:pwn_skills_path] || pwn_skills_path
      FileUtils.mkdir_p(pwn_skills_path) if pwn_skills_path && !Dir.exist?(pwn_skills_path.to_s)

      skills = {}
      return skills unless pwn_skills_path && Dir.exist?(pwn_skills_path.to_s)

      Dir.glob(File.join(pwn_skills_path, '*.{rb,md,txt,skill,yml,yaml}')).each do |skill_file|
        basename = File.basename(skill_file, '.*').to_sym
        content = File.read(skill_file)
        ext = File.extname(skill_file).downcase

        if ext == '.rb'
          begin
            require skill_file
            skills[basename] = { type: :ruby, path: skill_file, content: content, loaded: true, references: parse_skill_references(content: content) }
          rescue StandardError => e
            skills[basename] = { type: :ruby, path: skill_file, content: content, loaded: false, error: e.message, references: parse_skill_references(content: content) }
          end
        else
          skills[basename] = { type: :instruction, path: skill_file, content: content, references: parse_skill_references(content: content) }
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

        #{self}.refresh_env(
          pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
        pwn_dec_path: 'optional - Path to pwn.yaml.decryptor file.  Defaults to ~/.pwn/pwn.yaml.decryrptor'
        )

        #{self}.authors
      "
    end
  end
end
