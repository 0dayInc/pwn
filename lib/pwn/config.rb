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
          introspection: false,
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
              client_id: 'optional - xAI SuperGrok OAuth Client ID (for subscriptions without API key)',
              client_secret: 'optional - xAI SuperGrok OAuth Client Secret',
              access_token: 'optional - xAI SuperGrok OAuth Access Token (preferred for SuperGrok subs; used as Bearer)',
              refresh_token: 'optional - xAI SuperGrok OAuth Refresh Token',
              token_uri: 'optional - OAuth token endpoint (defaults handled in PWN::AI::Grok if needed)'
            }
          },
          openai: {
            base_uri: 'optional - Base URI for OpenAI - Use private base OR defaults to https://api.openai.com/v1',
            key: 'required - OpenAI API Key',
            model: 'optional - OpenAI model to use',
            system_role_content: 'You are an ethically hacking OpenAI agent.',
            temp: 'optional - OpenAI temperature',
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
            toolsets: nil
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
          irc: {
            ui_nick: '_human_',
            shared_chan: '#pwn',
            ai_agent_nicks: {
              browser: {
                pwn_rb: '/opt/pwn/lib/pwn/plugins/transparent_browser.rb',
                system_role_content: 'You are a browser.  You are a web browser that can be controlled by a human or AI agent'
              },
              nimjeh: {
                pwn_rb: '',
                system_role_content: 'You are a sarcastic hacker.  You find software zero day vulnerabilities. This involves analyzing source code, race conditions, application binaries, and network protocols from an offensive security perspective.'
              },
              nmap: {
                pwn_rb: '/opt/pwn/lib/pwn/plugins/nmap_it.rb',
                system_role_content: 'You are a network scanner.  You are a network scanner that can be controlled by a human or AI agent'
              },
              shodan: {
                pwn_rb: '/opt/pwn/lib/pwn/plugins/shodan.rb',
                system_role_content: 'You are a passive reconnaissance agent.  You are a passive reconnaissance agent that can be controlled by a human or AI agent'
              }
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

      sensitive_keys = %i[api_key key pass password psk token]

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

      valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :introspection }.map(&:downcase)

      engine = env[:ai][:active].to_s.downcase.to_sym
      raise "ERROR: Unsupported AI Engine: #{engine} in #{pwn_env_path}.  Supported AI Engines:\n#{valid_ai_engines.inspect}" unless valid_ai_engines.include?(engine)

      key = env[:ai][engine][:key]
      oauth_access = nil
      if engine == :grok
        oauth = env[:ai][engine][:oauth] ||= {}
        oauth_access = oauth[:access_token] if oauth[:access_token] && !oauth[:access_token].to_s.match?(/optional/i) && !oauth[:access_token].to_s.empty?
      end
      if key.nil? && oauth_access.nil?
        key = PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: "#{engine} API Key (or configure oauth:access_token in pwn-vault for xAI SuperGrok subscriptions)"
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
            skills[basename] = { type: :ruby, path: skill_file, content: content, loaded: true }
          rescue StandardError => e
            skills[basename] = { type: :ruby, path: skill_file, content: content, loaded: false, error: e.message }
          end
        else
          skills[basename] = { type: :instruction, path: skill_file, content: content }
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
