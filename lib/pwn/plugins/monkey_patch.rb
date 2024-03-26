# frozen_string_literal: true

module PWN
  module Plugins
    # This module provides the abilty to centralize monkey patches used in PWN
    module MonkeyPatch
      # Supported Method Parameters::
      # PWN::Plugins::MonkeyPatch.pry

      public_class_method def self.pry
        # Overwrite Pry::History.push method in History class
        # to get duplicate history entries in order to properly
        # replay automation in this prototyping driver
        Pry::History.class_eval do
          def push(line)
            return line if line.empty? || invalid_readline_line?(line)

            begin
              last_line = @history[-1]
            rescue IndexError
              last_line = nil
            end

            @history << line
            @history_line_count += 1
            @saver.call(line) if !should_ignore?(line) &&
                                 Pry.config.history_save

            line
          end
          alias << push
        end

        Pry.class_eval do
          def handle_line(line, options)
            if line.nil?
              config.control_d_handler.call(self)
              return
            end

            ensure_correct_encoding!(line)
            Pry.history << line unless options[:generated]

            @suppress_output = false
            inject_sticky_locals!
            begin
              # unless process_command_safely(line)
              unless process_command_safely(line) && (
                       line.empty? || @eval_string.empty?
                     )
                # @eval_string += "#{line.chomp}\n" if !line.empty? || !@eval_string.empty?
                @eval_string += "#{line.chomp}\n"
              end
            rescue RescuableException => e
              self.last_exception = e
              result = e

              Pry.critical_section do
                show_result(result)
              end
              return
            end

            # This hook is supposed to be executed after each line of ruby code
            # has been read (regardless of whether eval_string is yet a complete expression)
            exec_hook :after_read, eval_string, self

            begin
              complete_expr = true if config.pwn_ai || config.pwn_asm
              complete_expr = Pry::Code.complete_expression?(@eval_string) unless config.pwn_ai || config.pwn_asm
            rescue SyntaxError => e
              output.puts e.message.gsub(/^.*syntax error, */, 'SyntaxError: ')
              reset_eval_string
            end

            if complete_expr
              @suppress_output = true if @eval_string =~ /;\Z/ ||
                                         @eval_string.empty? ||
                                         @eval_string =~ /\A *#.*\n\z/ ||
                                         config.pwn_ai ||
                                         config.pwn_asm

              # A bug in jruby makes java.lang.Exception not rescued by
              # `rescue Pry::RescuableException` clause.
              #
              # * https://github.com/pry/pry/issues/854
              # * https://jira.codehaus.org/browse/JRUBY-7100
              #
              # Until that gets fixed upstream, treat java.lang.Exception
              # as an additional exception to be rescued explicitly.
              #
              # This workaround has a side effect: java exceptions specified
              # in `Pry.config.unrescued_exceptions` are ignored.
              jruby_exceptions = []
              jruby_exceptions << Java::JavaLang::Exception if Pry::Helpers::Platform.jruby?

              begin
                # Reset eval string, in case we're evaluating Ruby that does something
                # like open a nested REPL on this instance.
                eval_string = @eval_string
                reset_eval_string

                result = evaluate_ruby(eval_string) unless config.pwn_ai ||
                                                           config.pwn_asm

                result = eval_string if config.pwn_ai ||
                                        config.pwn_asm
              rescue RescuableException, *jruby_exceptions => e
                # Eliminate following warning:
                # warning: singleton on non-persistent Java type X
                # (http://wiki.jruby.org/Persistence)
                e.class.__persistent__ = true if Helpers::Platform.jruby? && e.class.respond_to?('__persistent__')
                self.last_exception = e
                result = e
              end

              Pry.critical_section do
                show_result(result)
              end
            end

            throw(:breakout) if current_binding.nil?
          end

          # Ensure the return value in pwn_ai mode reflects the input
          def evaluate_ruby(code)
            # if config.pwn_ai || config.pwn_asm
            #   result = message = code.to_s
            #   return
            # end
            inject_sticky_locals!
            exec_hook :before_eval, code, self

            result = current_binding.eval(code, Pry.eval_path, Pry.current_line)
            set_last_result(result, code)
          ensure
            update_input_history(code)
            exec_hook :after_eval, result, self
          end
        end
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.pry

          #{self}.authors
        "
      end
    end
  end
end
