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
            key: 'required - OpenAI API Key',
            model: 'optional - Grok model to use',
            system_role_content: 'You are an ethically hacking OpenAI agent.',
            temp: 'optional - OpenAI temperature'
          },
          openai: {
            base_uri: 'optional - Base URI for OpenAI - Use private base OR defaults to https://api.openai.com/v1',
            key: 'required - OpenAI API Key',
            model: 'optional - OpenAI model to use',
            system_role_content: 'You are an ethically hacking OpenAI agent.',
            temp: 'optional - OpenAI temperature'
          },
          ollama: {
            base_uri: 'required - Base URI for Open WebUI - e.g. https://ollama.local',
            key: 'required - Open WebUI API Key Under Settings  >> Account >> JWT Token',
            model: 'required - Ollama model to use',
            system_role_content: 'You are an ethically hacking Ollama agent.',
            temp: 'optional - Ollama temperature'
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
          jira_server: {
            base_uri: 'Jira Server Base API URI (e.g. https://jira.company.com/rest/api/latest)',
            token: 'Jira Server API Token'
          },
          meshtastic: {
            mqtt: {
              host: 'mqtt.meshtastic.org',
              port: 1883,
              user: 'meshdev',
              pass: 'large4cats'
            },
            channel: {
              LongFast: {
                psk: 'AQ==',
                region: 'US/<STATE>',
                channel_topic: '2/e/#'
              },
              PWN: {
                psk: 'required - PSK for pwn channel',
                region: 'US/<STATE>',
                channel_topic: '2/e/PWN/#'
              }
            }
          },
          shodan: { api_key: 'SHODAN API Key' }
        }
      }
      # Remove beginning colon from key names
      yaml_env = YAML.dump(env).gsub(/^(\s*):/, '\1')
      File.write(pwn_env_path, yaml_env)
      # Change file permission to 600
      File.chmod(0o600, pwn_env_path)

      env[:driver_opts] = {
        pwn_env_path: pwn_env_path,
        pwn_dec_path: pwn_dec_path
      }

      PWN::Plugins::Vault.create(
        file: pwn_env_path,
        decryptor_file: pwn_dec_path
      )

      Pry.config.refresh_pwn_env = false if defined?(Pry)
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
      FileUtils.mkdir_p(pwn_env_root)

      pwn_env_path = opts[:pwn_env_path] ||= "#{pwn_env_root}/pwn.yaml"
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
      if key.nil?
        key = PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: "#{engine} API Key"
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
