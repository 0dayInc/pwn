# frozen_string_literal: true

require 'tty-spinner'

module PWN
  module Plugins
    # Shared TTY::Spinner lifecycle for REST / AI calls.
    #
    # TTY::Spinner#stop marks @done and Thread#kills the auto_spin
    # worker but does NOT join it. The worker is typically mid-sleep
    # on its interval, so it stays alive long enough to write another
    # frame (cursor col 1 + glyph) over the HTTP response that the
    # caller is about to print. Creating the spinner with clear:false
    # (the gem default) also reprints the last glyph + newline on
    # stop, so the spinner appears to keep running whenever a
    # response is provided.
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

        TTY::Spinner.new(**args)
      end

      # Supported Method Parameters::
      # PWN::Plugins::TTYSpinner.stop(
      #   spin: 'optional - TTY::Spinner from #start (no-op if nil)'
      # )

      public_class_method def self.stop(opts = {})
        spin = opts.is_a?(Hash) ? opts[:spin] : opts
        return if spin.nil?

        spin.stop if spin.respond_to?(:stop)
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
