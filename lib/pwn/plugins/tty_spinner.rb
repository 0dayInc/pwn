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
    # frame (cursor col 1 + glyph) over the HTTP response / next PS1.
    #
    # #start owns the worker. #stop joins it. #halt_all! stops every
    # live spinner so a missed ensure cannot leave dots on the TTY.
    module TTYSpinner
      JOIN_SECS = 0.5
      LIVE = [] # rubocop:disable Style/MutableConstant
      LIVE_MUTEX = Mutex.new

      # Supported Method Parameters::
      # spin = PWN::Plugins::TTYSpinner.start(
      #   format: 'optional - TTY::Spinner format (defaults to :dots)',
      #   output: 'optional - IO to draw on (defaults to $stderr)'
      # )

      public_class_method def self.start(opts = {})
        args = {
          format: opts[:format] || :dots,
          clear: true,
          hide_cursor: false
        }
        args[:output] = if opts[:output]
                          opts[:output]
                        elsif defined?(PWN::Plugins::Log) && PWN::Plugins::Log.respond_to?(:raw_stderr)
                          PWN::Plugins::Log.raw_stderr
                        else
                          $stderr
                        end

        spin = TTY::Spinner.new(**args)
        halt_all!
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
        track(spin: spin)
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
        show_cursor(spin: spin)
        untrack(spin: spin)
        nil
      end

      # Supported Method Parameters::
      # PWN::Plugins::TTYSpinner.halt_all!

      public_class_method def self.halt_all!(opts = {})
        return nil unless opts.is_a?(Hash)

        list = LIVE_MUTEX.synchronize { LIVE.dup }
        list.each { |spin| stop(spin: spin) }
        nil
      end

      private_class_method def self.track(opts = {})
        spin = opts[:spin]
        return unless spin

        LIVE_MUTEX.synchronize do
          LIVE.reject! { |s| spinner_dead?(spin: s) }
          LIVE << spin unless LIVE.include?(spin)
        end
      rescue StandardError
        nil
      end

      private_class_method def self.untrack(opts = {})
        spin = opts[:spin]
        LIVE_MUTEX.synchronize { LIVE.delete(spin) }
      rescue StandardError
        nil
      end

      private_class_method def self.spinner_dead?(opts = {})
        spin = opts[:spin]
        return true if spin.nil?
        return true if spin.respond_to?(:done?) && spin.done?

        worker = spin.respond_to?(:pwn_worker_thread) ? spin.pwn_worker_thread : nil
        worker.is_a?(Thread) && !worker.alive?
      rescue StandardError
        true
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

      private_class_method def self.show_cursor(opts = {})
        spin = opts[:spin]
        show = defined?(TTY::Cursor) ? TTY::Cursor.show : "\e[?25h"
        out = spin.output if spin.respond_to?(:output)
        out.print(show) if out.respond_to?(:print)
        $stdout.write(show) if $stdout.respond_to?(:write)
        $stdout.flush if $stdout.respond_to?(:flush)
        $stderr.write(show) if $stderr.respond_to?(:write)
        $stderr.flush if $stderr.respond_to?(:flush)
      rescue StandardError
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
          #{self}.halt_all!
        "
      end
    end
  end
end
