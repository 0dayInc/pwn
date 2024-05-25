# frozen_string_literal: true

require 'pry'
require 'tty-prompt'
require 'yaml'

module PWN
  module Plugins
    # This module contains methods related to the pwn REPL Driver.
    module REPL
      # Supported Method Parameters::
      # PWN::Plugins::REPL.refresh_ps1_proc(
      #   mode: 'required - :splat or nil'
      # )

      public_class_method def self.refresh_ps1_proc(opts = {})
        mode = opts[:mode]

        proc do |_target_self, _nest_level, pi|
          pi.config.pwn_repl_line += 1
          line_pad = format(
            '%0.3d',
            pi.config.pwn_repl_line
          )

          pi.config.prompt_name = :pwn
          name = "\001\e[1m\002\001\e[31m\002#{pi.config.prompt_name}\001\e[0m\002"
          version = "\001\e[36m\002v#{PWN::VERSION}\001\e[0m\002"
          line_count = "\001\e[34m\002#{line_pad}\001\e[0m\002"
          dchars = "\001\e[32m\002>>>\001\e[0m\002"
          dchars = "\001\e[33m\002***\001\e[0m\002" if mode == :splat

          if pi.config.pwn_asm
            pi.config.prompt_name = 'pwn.asm'
            name = "\001\e[1m\002\001\e[37m\002#{pi.config.prompt_name}\001\e[0m\002"
            dchars = "\001\e[32m\002>>>\001\e[33m\002"
            dchars = "\001\e[33m\002***\001\e[33m\002" if mode == :splat
          end

          if pi.config.pwn_ai
            ai_engine = pi.config.pwn_ai_engine
            model = pi.config.pwn_ai_model
            pname = "pwn.ai:#{ai_engine}"
            pname = "pwn.ai:#{ai_engine}/#{model}" if model
            pname = "pwn.ai:#{ai_engine}/#{model}.SPEAK" if pi.config.pwn_ai_speak
            pi.config.prompt_name = pname

            name = "\001\e[1m\002\001\e[33m\002#{pi.config.prompt_name}\001\e[0m\002"
            dchars = "\001\e[32m\002>>>\001\e[33m\002"
            dchars = "\001\e[33m\002***\001\e[33m\002" if mode == :splat
            if pi.config.pwn_ai_debug
              dchars = "\001\e[32m\002(DEBUG) >>>\001\e[33m\002"
              dchars = "\001\e[33m\002(DEBUG) ***\001\e[33m\002" if mode == :splat
            end
          end

          "#{name}[#{version}]:#{line_count} #{dchars} ".to_s.scrub
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.add_commands

      public_class_method def self.add_commands
        # Define Custom REPL Commands
        Pry::Commands.create_command 'welcome-banner' do
          description 'Display the random welcome banner, including basic usage.'

          def process
            puts PWN::Banner.welcome
          end
        end

        Pry::Commands.create_command 'toggle-pager' do
          description 'Toggle less on returned objects surpassing the terminal.'

          def process
            pi = pry_instance
            pi.config.pager ? pi.config.pager = false : pi.config.pager = true
          end
        end

        #  class PWNCompleter < Pry::InputCompleter
        #    def call(input)
        #    end
        #  end

        Pry::Commands.create_command 'pwn-asm' do
          description 'Initiate pwn.asm shell.'

          def process
            pi = pry_instance
            pi.config.pwn_asm = true
            pi.custom_completions = proc do
              prompt = TTY::Prompt.new
              [pi.input.line_buffer]
              # prompt.select(pi.input.line_buffer)
            end
          end
        end

        Pry::Commands.create_command 'pwn-ai' do
          description 'Initiate pwn.ai chat interface.'

          def process
            pi = pry_instance
            pi.config.pwn_ai = true
            pi.config.color = false if pi.config.pwn_ai
            pi.config.color = true unless pi.config.pwn_ai
          end
        end

        Pry::Commands.create_command 'pwn-irc' do
          description 'Initiate pwn.irc chat interface.'

          def process
            pi = pry_instance
            inspircd_listening = PWN::Plugins::Sock.check_port_in_use(server_ip: '127.0.0.1', port: 6667)
            return unless File.exist?('/usr/bin/irssi') && inspircd_listening

            # TODO: Initialize inspircd on localhost:6667 using
            # PWN::Plugins::IRC && PWN::Plugins::ThreadPool modules.
            system('/usr/bin/irssi -c 127.0.0.1 -p 6667 -n pwn-irc')
          end
        end

        Pry::Commands.create_command 'toggle-pwn-ai-debug' do
          description 'Display the response_history object while using pwn.ai'

          def process
            pi = pry_instance
            pi.config.pwn_ai_debug ? pi.config.pwn_ai_debug = false : pi.config.pwn_ai_debug = true
          end
        end

        Pry::Commands.create_command 'toggle-pwn-ai-speaks' do
          description 'Use speech capabilities within pwn.ai to speak answers.'

          def process
            pi = pry_instance
            pi.config.pwn_ai_speak ? pi.config.pwn_ai_speak = false : pi.config.pwn_ai_speak = true
          end
        end

        Pry::Commands.create_command 'back' do
          description 'Jump back to pwn REPL when in pwn-asm || pwn-ai.'

          def process
            pi = pry_instance
            pi.config.color = true
            pi.config.pwn_asm = false if pi.config.pwn_asm
            pi.config.pwn_ai = false if pi.config.pwn_ai
            pi.config.pwn_ai_debug = false if pi.config.pwn_ai_debug
            pi.config.pwn_ai_speak = false if pi.config.pwn_ai_speak
            pi.config.completer = Pry::InputCompleter
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.add_hooks(
      #   opts: 'required - Hash object passed in via pwn OptParser'
      # )

      public_class_method def self.add_hooks(opts = {})
        # Define REPL Hooks
        # Welcome Banner Hook
        Pry.config.hooks.add_hook(:before_session, :welcome) do |output, _binding, _pi|
          output.puts PWN::Banner.welcome
        end

        # Initialize pwn.yaml Configuration using :before_session Hook
        Pry.config.hooks.add_hook(:before_session, :init_opts) do |_output, _binding, pi|
          if opts[:yaml_config_path] && File.exist?(opts[:yaml_config_path])
            yaml_config_path = opts[:yaml_config_path]
            is_encrypted = PWN::Plugins::Vault.file_encrypted?(file: yaml_config_path)

            if is_encrypted
              # TODO: Implement "something you know, something you have, && something you are?"
              decryption_file = opts[:decryption_file] ||= "#{Dir.home}/pwn.decryptor.yaml"
              yaml_decryptor = YAML.load_file(decryption_file, symbolize_names: true) if File.exist?(decryption_file)

              key = opts[:key] ||= yaml_decryptor[:key] ||= ENV.fetch('PWN_DECRYPTOR_KEY')
              key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption Key') if key.nil?

              iv = opts[:iv] ||= yaml_decryptor[:iv] ||= ENV.fetch('PWN_DECRYPTOR_IV')
              iv = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption IV') if iv.nil?

              yaml_config = PWN::Plugins::Vault.dump(
                file: yaml_config_path,
                key: key,
                iv: iv
              )
            else
              yaml_config = YAML.load_file(yaml_config_path, symbolize_names: true)
            end
            pi.config.p = yaml_config
            Pry.config.p = yaml_config

            valid_ai_engines = %i[
              openai
              ollama
            ]
            ai_engine = yaml_config[:ai_engine].to_s.to_sym

            raise "ERROR: Unsupported AI Engine: #{ai_engine} in #{yaml_config_path}" unless valid_ai_engines.include?(ai_engine)

            pi.config.pwn_ai_engine = ai_engine
            Pry.config.pwn_ai_engine = ai_engine

            pi.config.pwn_ai_fqdn = pi.config.p[ai_engine][:fqdn]
            Pry.config.pwn_ai_fqdn = pi.config.pwn_ai_fqdn

            pi.config.pwn_ai_key = pi.config.p[ai_engine][:key]
            Pry.config.pwn_ai_key = pi.config.pwn_ai_key

            pi.config.pwn_ai_model = pi.config.p[ai_engine][:model]
            Pry.config.pwn_ai_model = pi.config.pwn_ai_model

            true
          end
        end

        Pry.config.hooks.add_hook(:after_read, :pwn_asm_hook) do |request, pi|
          if pi.config.pwn_asm && !request.chomp.empty?
            request = pi.input.line_buffer

            # Analyze request to determine if it should be processed as opcodes or asm.
            straight_hex = /^[a-fA-F0-9\s]+$/
            hex_esc_strings = /\\x[\da-fA-F]{2}/
            hex_comma_delim_w_dbl_qt = /"(?:[0-9a-fA-F]{2})",?/
            hex_comma_delim_w_sng_qt = /'(?:[0-9a-fA-F]{2})',?/
            hex_byte_array_as_str = /^\[\s*(?:"[0-9a-fA-F]{2}",\s*)*"[0-9a-fA-F]{2}"\s*\]$/

            if request.match?(straight_hex) ||
               request.match?(hex_esc_strings) ||
               request.match?(hex_comma_delim_w_dbl_qt) ||
               request.match?(hex_comma_delim_w_sng_qt) ||
               request.match?(hex_byte_array_as_str)

              response = PWN::Plugins::Assembly.opcodes_to_asm(
                opcodes: request,
                opcodes_always_strings_obj: true
              )
            else
              response = PWN::Plugins::Assembly.asm_to_opcodes(asm: request)
            end
            puts "\001\e[31m\002#{response}\001\e[0m\002"
          end
        end

        Pry.config.hooks.add_hook(:after_read, :pwn_ai_hook) do |request, pi|
          if pi.config.pwn_ai && !request.chomp.empty?
            request = pi.input.line_buffer.to_s
            debug = pi.config.pwn_ai_debug
            ai_engine = pi.config.pwn_ai_engine.to_s.to_sym
            ai_key = pi.config.pwn_ai_key
            ai_key ||= ''
            if ai_key.empty?
              ai_key = PWN::Plugins::AuthenticationHelper.mask_password(
                prompt: 'pwn-ai Key'
              )
              pi.config.pwn_ai_key = ai_key
            end

            response_history = pi.config.pwn_ai_response_history
            speak_answer = pi.config.pwn_ai_speak
            model = pi.config.pwn_ai_model

            case ai_engine
            when :ollama
              fqdn = pi.config.pwn_ai_fqdn

              response = PWN::Plugins::Ollama.chat(
                fqdn: fqdn,
                token: ai_key,
                model: model,
                request: request.chomp,
                response_history: response_history,
                speak_answer: speak_answer
              )
            when :openai
              response = PWN::Plugins::OpenAI.chat(
                token: ai_key,
                model: model,
                request: request.chomp,
                response_history: response_history,
                speak_answer: speak_answer
              )
            else
              raise "ERROR: Unsupported AI Engine: #{ai_engine}"
            end

            last_response = response[:choices].last[:content]
            puts "\n\001\e[32m\002#{last_response}\001\e[0m\002\n\n"

            response_history = {
              id: response[:id],
              object: response[:object],
              model: response[:model],
              usage: response[:usage]
            }
            response_history[:choices] ||= response[:choices]

            if debug
              puts 'DEBUG: response_history => '
              pp response_history
              puts "\nresponse_history[:choices] Length: #{response_history[:choices].length}\n" unless response_history.nil?
            end
            pi.config.pwn_ai_response_history = response_history
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.start(
      #   opts: 'required - Hash object passed in via pwn OptParser'
      # )

      public_class_method def self.start(opts = {})
        # Monkey Patch Pry, add commands, && hooks
        PWN::Plugins::MonkeyPatch.pry
        add_commands
        add_hooks(opts)

        # Define PS1 Prompt
        Pry.config.pwn_repl_line = 0
        Pry.config.prompt_name = :pwn
        arrow_ps1_proc = refresh_ps1_proc
        splat_ps1_proc = refresh_ps1_proc(mode: :splat)
        ps1 = [arrow_ps1_proc, splat_ps1_proc]
        prompt = Pry::Prompt.new(:pwn, 'PWN Prototyping REPL', ps1)

        # Start PWN REPL
        # Pry.start(self, prompt: prompt)
        Pry.start(Pry.main, prompt: prompt)
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
          #{self}.refresh_ps1_proc(
            mode: 'required - :splat or nil'
          )

          #{self}.add_commands

          #{self}.add_hooks(
            opts: 'required - Hash object passed in via pwn OptParser'
          )

          #{self}.start(
            opts: 'required - Hash object passed in via pwn OptParser'
          )

          #{self}.authors
        "
      end
    end
  end
end
