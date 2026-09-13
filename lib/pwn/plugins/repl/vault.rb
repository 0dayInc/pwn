# frozen_string_literal: true

require 'yaml'
require 'pry'

module PWN
  module Plugins
    module REPL
      # pwn-vault REPL mode.
      module Vault
        # Register Pry commands for this REPL mode.
        public_class_method def self.add_commands
          Pry::Commands.create_command 'pwn-vault' do
            description 'Edit the pwn.yaml configuration file.'

            def process
              pwn_env_path = PWN::Env[:driver_opts][:pwn_env_path] ||= "#{Dir.home}/.pwn/pwn.yaml"
              unless File.exist?(pwn_env_path)
                puts "ERROR: pwn environment file not found: #{pwn_env_path}"
                return
              end

              # Prefer driver_opts (set by Config.refresh_env); fall back to the
              # canonical sidecar path Config uses: <pwn.yaml>.decryptor
              pwn_dec_path = PWN::Env[:driver_opts][:pwn_dec_path] ||= "#{pwn_env_path}.decryptor"
              unless File.exist?(pwn_dec_path)
                puts "ERROR: pwn decryptor file not found: #{pwn_dec_path}"
                return
              end

              decryptor = YAML.load_file(pwn_dec_path, symbolize_names: true)
              key = decryptor[:key]
              iv = decryptor[:iv]

              # Vault.edit decrypts -> opens editor -> encrypts and only sets
              # Pry.config.refresh_pwn_env = true. PWN::Config.refresh_env (which
              # raises RuntimeError on invalid pwn.yaml) historically ran later in
              # the PS1 hook, OUTSIDE this command - so the old rescue/retry never
              # saw Config errors. Validate here: on RuntimeError print the error,
              # prompt "Press Enter to Resolve", wait on $stdin.gets, then re-open
              # the editor until the vault loads cleanly.
              loop do
                PWN::Plugins::Vault.edit(
                  file: pwn_env_path,
                  key: key,
                  iv: iv
                )

                begin
                  PWN::Config.refresh_env(
                    pwn_env_path: pwn_env_path,
                    pwn_dec_path: pwn_dec_path,
                    key: key,
                    iv: iv
                  )
                  break
                rescue RuntimeError => e
                  # Keep the prior in-memory Env usable if the operator aborts
                  # further edits; otherwise the next PS1 tick would raise again.
                  Pry.config.refresh_pwn_env = false if defined?(Pry)
                  print "\001\e[33m\002"
                  puts e.message
                  print 'Press ENTER to resolve...'
                  print "\001\e[0m\002\s"
                  $stdin.gets
                end
              end
            rescue StandardError => e
              raise e
            end
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display usage for this module.

        public_class_method def self.help
          puts "USAGE:
            # Register the pwn-vault Pry command.
            #{self}.add_commands

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
