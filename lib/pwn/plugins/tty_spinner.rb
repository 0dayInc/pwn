# frozen_string_literal: true

require 'tty-spinner'
require 'tty-cursor'

module PWN
  module Plugins
    # Shared TTY::Spinner lifecycle for REST / AI calls.
    #
    # TTY::Spinner#stop marks @done and Thread#kills the auto_spin
    # worker but does NOT join it. The worker is typically mid-sleep
    # on its interval, so it stays alive long enough to write another
    # frame (cursor col 1 + glyph) over the HTTP response that the
    # caller is about to print.
    #
    # #start uses clear:true + hide_cursor and owns the worker
    # (spin.start + Thread.new { spin.spin until spin.done? }).
    # #stop captures that thread, calls spin.stop, force-halts on
    # error, kills if still alive, joins (re-kill on timeout), then
    # clear_line + cursor show after the worker is dead.
    module TTYSpinner
      JOIN_SECS = 0.5

      # Supported Method Parameters::
      # spin = PWN::Plugins::TTYSpinner.start(
      #   format: 'optional - TTY::Spinner format (defaults to :dots)',
      #   output: 'optional - IO to draw on (defaults to $stderr)'
      # )

      public_class_method def self.start(opts = {})
        args = {
          format: opts[:format] || :dots,
          clear: true,
          hide_cursor: true
        }
        args[:output] = opts[:output] unless opts[:output].nil?

        spin = TTY::Spinner.new(**args)
        spin.start
        interval = 1.0 / [spin.interval.to_f, 1.0].max
        worker = Thread.new do
          Thread.current.report_on_exception = false
          until spin.done?
            spin.spin
            sleep(interval)
          end
        end
        spin.define_singleton_method(:pwn_worker_thread) { worker }
        spin
      end

      # Supported Method Parameters::
      # PWN::Plugins::TTYSpinner.stop(
      #   spin: 'optional - TTY::Spinner from #start (no-op if nil)'
      # )

      public_class_method def self.stop(opts = {})
        spin = opts.is_a?(Hash) ? opts[:spin] : opts
        return if spin.nil?

        worker = spin.respond_to?(:pwn_worker_thread) ? spin.pwn_worker_thread : nil
        begin
          spin.stop if spin.respond_to?(:stop)
        rescue StandardError
          spin.kill if spin.respond_to?(:kill)
        end
        join_thread(thread: worker)
        join_spinner(spin: spin)
        begin
          spin.clear_line if spin.respond_to?(:clear_line)
          show = defined?(TTY::Cursor) ? TTY::Cursor.show : "\e[?25h"
          out = spin.output if spin.respond_to?(:output)
          out.print(show) if out.respond_to?(:print)
          $stdout.write(show) if $stdout.respond_to?(:write)
          $stdout.flush if $stdout.respond_to?(:flush)
        rescue StandardError
          nil
        end
        nil
      end

      private_class_method def self.join_thread(opts = {})
        thread = opts[:thread]
        return unless thread.is_a?(Thread)
        return unless thread.alive?

        unless thread.join(JOIN_SECS)
          thread.kill
          thread.join(JOIN_SECS)
        end
      rescue StandardError
        thread.kill if thread.respond_to?(:kill)
      end

      private_class_method def self.join_spinner(opts = {})
        spin = opts[:spin]
        return unless spin.respond_to?(:join)

        spin.join(JOIN_SECS)
      rescue TTY::Spinner::NotSpinningError, StandardError
        nil
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display usage info

      public_class_method def self.help
        puts "USAGE:
          spin = #{self}.start
          #{self}.stop(spin: spin)
        "
      end
    end
  end
end
