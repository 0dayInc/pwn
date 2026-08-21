# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'logger'
require 'securerandom'

module PWN
  module Plugins
    # This plugin is used to instantiate a PWN logger with a custom message format
    module Log
      TRACE_SKIP_METHODS = %i[
        authors help to_s inspect class object_id hash eql? == equal? !
        method public_send send __send__ instance_eval class_eval
        public_class_method private_class_method
        debug_on? debug_progress start_debug_session quiet_debug_tui!
        loud_debug_tui! budget_scar? effective_count safe_check
        rank_for_request usable_preference? cause_crumb
      ].freeze
      TRACE_SKIP_PREFIXES = %w[
        PWN::Plugins::Log
        PWN::Plugins::REPL
        PWN::Banner
      ].freeze
      DEFAULT_TRACE_PREFIXES = %w[
        PWN::AI
        PWN::Memory
        PWN::Sessions
        PWN::Config
        PWN::Cron
        PWN::Plugins
      ].freeze
      SECRET_KEY_RX = /password|passwd|secret|token|api[_-]?key|authorization|bearer|cookie|session[_-]?id|private[_-]?key|decryptor|credential|ssh[_-]?key|client[_-]?secret|refresh[_-]?token|access[_-]?token|id[_-]?token|vault|csrf/i
      SECRET_VALUE_RX = %r{
        -----BEGIN\ [A-Z ]*PRIVATE\ KEY----- |
        Bearer\s+[A-Za-z0-9\-._~+/]+=* |
        \beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+ |
        \b(?:sk|rk|pk|xai|xox[baprs]|ghp|gho|ghu|ghs|ghr|glpat|AKIA|ASIA|ya29)[-_][A-Za-z0-9\-_]{16,} |
        \b(?:api[_-]?key|token|secret|password|passwd)\s*[:=]\s*\S+
      }ix
      DEBUG_VALUE_MAX = 240
      DEBUG_ARGS_MAX = 1_800

      # Supported Method Parameters::
      # PWN::Log.create(
      # )
      public_class_method def self.append(opts = {})
        level = opts[:level].to_s.downcase.to_sym
        msg = opts[:msg]
        which_self = opts[:which_self].to_s

        driver_name = File.basename($PROGRAM_NAME)

        # Only attempt to exit gracefully if level == :error
        exit_gracefully = false

        # Define Date / Time Format
        datetime_str = '%Y-%m-%d %H:%M:%S.%N%z'

        # Always append to log file
        if level == :learning
          session = SecureRandom.hex
          log_file_path = "/tmp/pwn-ai-#{session}.json" if level == :learning
          log_file = File.open(log_file_path, 'w')
        else
          log_file_path = '/tmp/pwn.log'
          log_file = File.open(log_file_path, 'a')
        end

        # Leave 10 "old" log files where
        # each file is ~ 1,024,000 bytes
        logger = Logger.new(
          log_file,
          10,
          1_024_000
        )
        logger.datetime_format = datetime_str

        case level
        when :debug
          logger.level = Logger::DEBUG
        when :error
          logger.level = Logger::ERROR
          exit_gracefully = true unless driver_name == 'pwn'
          puts "\nERROR: See #{log_file_path} for more details." if driver_name == 'pwn'
        when :fatal
          logger.level = Logger::FATAL
          puts "\n FATAL ERROR: See #{log_file_path} for more details." if driver_name == 'pwn'
        when :info, :learning
          logger.level = Logger::INFO
        when :unknown
          logger.level = Logger::UNKNOWN
        when :warn
          logger.level = Logger::WARN
        else
          level_error = "ERROR: Invalid log level. Valid options are:\n"
          level_error += ":debug\n:error\n:fatal\n:info\n:learning\n:unknown\n:warn\n"
          raise level_error
        end

        if level == :learning
          log_event = msg
          logger.formatter = proc do |_severity, _datetime, _progname, learning_arr|
            JSON.pretty_generate(
              learning_data: learning_arr
            )
          end
        else
          log_event = "driver: #{driver_name}"

          if msg.instance_of?(Interrupt)
            logger.level = Logger::WARN
            note_interrupt!(where: 'CTRL+C', which_self: which_self) if debug_enabled?
            if driver_name == 'pwn'
              log_event += ' => CTRL+C Detected.'
            else
              log_event += ' => CTRL+C Detected...Exiting Session.'
              exit_gracefully = true unless driver_name == 'pwn'
            end
          else
            log_event += " => #{msg}"
            if msg.respond_to?('backtrace') && !msg.instance_of?(Errno::ECONNRESET)
              log_event += " => \n\t#{msg.backtrace.join("\n\t")}"
              log_event += "\n\n\n"
            end
          end
        end

        logger.add(logger.level, log_event, which_self)
      rescue Interrupt
        note_interrupt!(where: 'CTRL+C', which_self: self) if debug_enabled?
        puts "\n#{self}.#{__method__} => Goodbye."
      rescue StandardError => e
        raise e
      end

      public_class_method def self.debug_enabled?(opts = {})
        return @debug_enabled == true if opts.is_a?(Hash)

        @debug_enabled == true
      end

      public_class_method def self.debug_log_path(opts = {})
        return @debug_path if opts.is_a?(Hash)

        @debug_path
      end

      # Open a debug session. Request traces go to
      # /tmp/pwn-ai-DEBUG-<session_id>-RN.log via next_request_log!.
      # opts[:path] is a test override that writes to one file.
      public_class_method def self.start_debug(opts = {})
        if debug_enabled? && opts[:path].to_s.empty?
          @debug_tee = opts[:tee] if opts.key?(:tee)
          sid = sanitize_debug_session_id(session_id: opts[:session_id])
          @debug_session_id = sid unless sid.empty?
          return @debug_path
        end

        stop_trace! if @debug_tp
        path = opts[:path].to_s
        @debug_tee = opts[:tee]
        @debug_tui_quiet = false
        @debug_enabled = true
        @debug_session_id = sanitize_debug_session_id(session_id: opts[:session_id])
        @debug_req_n = 0
        @debug_request_open = false
        if path.empty?
          close_debug_file!
          @debug_path = nil
        else
          open_debug_file!(path: path)
        end
        start_trace!(prefixes: opts[:prefixes]) if opts[:trace] == true
        install_stderr_tee!
        progress(msg: 'debug session start', which_self: self) if @debug_file
        @debug_path
      end

      public_class_method def self.next_request_log!(opts = {})
        return unless debug_enabled?
        return @debug_path if @debug_request_open && opts[:force] != true

        sid = sanitize_debug_session_id(session_id: opts[:session_id])
        sid = @debug_session_id if sid.empty?
        sid = 'nosession' if sid.empty?
        @debug_session_id = sid
        n = next_debug_request_n(session_id: sid)
        path = "/tmp/pwn-ai-DEBUG-#{sid}-R#{n}.log"
        open_debug_file!(path: path)
        @debug_req_n = n
        @debug_request_open = true
        progress(msg: "request log R#{n} path=#{path}", which_self: self)
        path
      end

      public_class_method def self.finish_request_log!(opts = {})
        return unless debug_enabled?
        return unless @debug_request_open || opts[:force] == true

        bits = [
          "footer iter=#{opts[:iter].to_i}",
          "tools_called=#{opts[:tools_called].to_i}",
          "engine_s=#{opts[:engine_s].to_f.round(3)}",
          "final_chars=#{opts[:final_chars].to_i}"
        ]
        bits << "nested=#{opts[:nested]}" unless opts[:nested].to_s.empty?
        progress(msg: bits.join(' '), which_self: self)
        @debug_request_open = false
        @debug_path
      end

      public_class_method def self.stop_debug(opts = {})
        reason = opts[:reason].to_s if opts.is_a?(Hash)
        if debug_enabled?
          tail = reason.to_s.empty? ? 'debug session stop' : "debug session stop reason=#{reason}"
          progress(msg: tail, which_self: self)
        end
        stop_trace!
        path = @debug_path
        close_debug_file!
        @debug_path = nil
        @debug_session_id = nil
        @debug_req_n = nil
        @debug_request_open = false
        @debug_tee = nil
        @debug_tui_quiet = false
        @debug_enabled = false
        remove_stderr_tee!
        path
      end

      # Ruby Thread.report_on_exception dumps IOError to $stderr. Clone that
      # (and any other stderr from pwn-ai) into the open RN request log.
      class DebugStderrTee
        def initialize(opts = {})
          @orig = opts[:orig] || $stderr
        end

        def write(*args)
          data = args.join
          begin
            @orig.write(data) if @orig.respond_to?(:write)
          rescue StandardError
            nil
          end
          PWN::Plugins::Log.capture_stderr!(text: data)
          data.bytesize
        end

        def <<(obj)
          write(obj.to_s)
          self
        end

        def puts(*args)
          if args.empty?
            write("\n")
          else
            args.each { |a| write("#{a}\n") }
          end
          nil
        end

        def print(*args)
          write(args.join)
          nil
        end

        def flush
          @orig.flush if @orig.respond_to?(:flush)
          self
        end

        def tty?
          @orig.respond_to?(:tty?) && @orig.tty?
        end

        def fileno
          @orig.fileno if @orig.respond_to?(:fileno)
        end

        def close
          nil
        end

        def closed?
          false
        end

        def sync
          @orig.respond_to?(:sync) ? @orig.sync : true
        end

        def sync=(val)
          @orig.sync = val if @orig.respond_to?(:sync=)
          val
        end

        def to_io
          @orig.respond_to?(:to_io) ? @orig.to_io : @orig
        end

        def respond_to_missing?(mid, include_all = false)
          @orig.respond_to?(mid, include_all)
        end

        def method_missing(mid, ...)
          @orig.public_send(mid, ...)
        end
      end

      public_class_method def self.capture_stderr!(opts = {})
        return unless debug_enabled?
        return if Thread.current[:pwn_log_stderr]

        text = opts[:text].to_s
        return if text.empty?
        return if spinner_frame?(text: text)

        Thread.current[:pwn_log_stderr] = true
        begin
          io = @debug_file
          return if io.nil? || (io.respond_to?(:closed?) && io.closed?)

          clean = sanitize_debug_text(text: text.gsub(/\e\[[0-9;]*m/, ''))
          return if clean.strip.empty?
          return if spinner_frame?(text: clean)

          io.write(clean.end_with?("\n") ? clean : "#{clean}\n")
          io.flush
        rescue StandardError
          nil
        ensure
          Thread.current[:pwn_log_stderr] = false
        end
        clean
      end

      # Spinner frames stay on the TTY; never persist them in the RN log.
      public_class_method def self.spinner_frame?(opts = {})
        raw = opts[:text].to_s
        return false if raw.empty?

        stripped = raw.gsub(/\e\[[0-9;?]*[A-Za-z]/, '').delete("\r").delete("\b")
        stripped = stripped.gsub(/[\u2800-\u28FF]/, '')
        stripped.strip.empty?
      end

      public_class_method def self.raw_stderr(opts = {})
        return @debug_stderr_orig if opts.is_a?(Hash) && @debug_stderr_orig

        $stderr
      end

      private_class_method def self.install_stderr_tee!(opts = {})
        return if opts[:skip]
        return if defined?(@debug_stderr_tee) && @debug_stderr_tee && $stderr.equal?(@debug_stderr_tee)

        @debug_stderr_orig = $stderr
        @debug_stderr_tee = DebugStderrTee.new(orig: $stderr)
        $stderr = @debug_stderr_tee
        @debug_stderr_tee
      end

      private_class_method def self.remove_stderr_tee!(opts = {})
        return if opts[:skip]
        return unless @debug_stderr_tee

        $stderr = @debug_stderr_orig if $stderr.equal?(@debug_stderr_tee)
        @debug_stderr_tee = nil
        @debug_stderr_orig = nil
      end

      private_class_method def self.sanitize_debug_session_id(opts = {})
        opts[:session_id].to_s.gsub(/[^A-Za-z0-9._-]/, '_')[0, 80]
      end

      private_class_method def self.next_debug_request_n(opts = {})
        sid = sanitize_debug_session_id(session_id: opts[:session_id])
        max_n = 0
        Dir.glob("/tmp/pwn-ai-DEBUG-#{sid}-R*.log").each do |p|
          n = p[/-R(\d+)\.log\z/, 1].to_i
          max_n = n if n > max_n
        end
        max_n + 1
      end

      private_class_method def self.close_debug_file!(opts = {})
        return if opts[:skip]

        begin
          @debug_file&.close unless @debug_file.nil? || @debug_file.closed?
        rescue StandardError
          nil
        end
        @debug_file = nil
      end

      private_class_method def self.open_debug_file!(opts = {})
        path = opts[:path].to_s
        return if path.empty?

        close_debug_file!
        FileUtils.mkdir_p(File.dirname(path))
        io = File.open(path, 'a')
        io.sync = true
        @debug_file = io
        @debug_path = path
        path
      end

      public_class_method def self.quiet_tui!(opts = {})
        return if opts[:skip]

        @debug_tui_quiet = true
      end

      public_class_method def self.loud_tui!(opts = {})
        return if opts[:skip]

        @debug_tui_quiet = false
      end

      # One progress line to the debug file and the TUI tee (same payload).
      public_class_method def self.progress(opts = {})
        return false unless debug_enabled?
        return false if Thread.current[:pwn_log_progress]

        Thread.current[:pwn_log_progress] = true
        msg = sanitize_debug_text(text: opts[:msg].to_s)
        which = opts[:which_self] || self
        line = format_progress(
          msg: msg,
          which_self: which,
          keep_newlines: opts[:keep_newlines],
          cap: opts[:cap]
        )
        begin
          @debug_file&.puts(line)
          @debug_file&.flush
        rescue StandardError
          nil
        end
        tee = opts.key?(:tee) ? opts[:tee] : @debug_tee
        if !@debug_tui_quiet && tee.respond_to?(:puts)
          begin
            tee.puts(color_progress(line: line))
            tee.flush if tee.respond_to?(:flush)
            $stdout.flush if $stdout.respond_to?(:flush)
          rescue StandardError
            nil
          end
        end
        true
      ensure
        Thread.current[:pwn_log_progress] = false
      end

      public_class_method def self.note_interrupt!(opts = {})
        return false unless debug_enabled?

        where = opts[:where].to_s
        where = 'CTRL+C' if where.empty?
        # CTRL+C can land mid-progress (HTTP spinner tee, tool row mirror).
        # Clear the reentrancy latch so the Interrupt stamp always lands in the
        # open RN file before the ensure footer / process unwind.
        Thread.current[:pwn_log_progress] = false
        at = Time.now
        local_ts = at.strftime('%Y-%m-%d %H:%M:%S.%L%z')
        msg = "Interrupt #{where} at=#{at.utc.iso8601(3)}"
        which = opts[:which_self] || self
        # Prefer the normal DEBUG stamp path; fall back to a direct file write
        # if progress is still unavailable for any reason.
        ok = progress(msg: msg, which_self: which)
        unless ok
          begin
            who = which.is_a?(Module) ? (which.name || which.to_s) : which.to_s
            line = "[DEBUG #{local_ts}] #{who} #{msg}".strip
            @debug_file&.puts(line)
            @debug_file&.flush
            ok = true
          rescue StandardError
            ok = false
          end
        end
        # Also clone the operator-facing TUI shape into the RN file.
        mirror_tui!(msg: "[ #{local_ts} → pwn-ai → Interrupt ] #{where}")
        ok
      end

      public_class_method def self.note_exception!(opts = {})
        return false unless debug_enabled?

        err = opts[:error]
        return false unless err.respond_to?(:message)

        where = opts[:where].to_s
        where = 'Loop.run' if where.empty?
        bt = Array(err.backtrace).join("\n")
        progress(
          msg: "exception #{where} #{err.class}: #{err.message}\n#{bt}",
          which_self: opts[:which_self] || self,
          keep_newlines: true,
          cap: 0
        )
      end

      # Clone operator-visible TUI rows into the open RN request log (no ANSI).
      # Used for [ ts → pwn-ai → tool ] / → result / task briefs so the file
      # matches what the operator saw without needing a TracePoint dump.
      public_class_method def self.mirror_tui!(opts = {})
        return unless debug_enabled?
        return unless opts.is_a?(Hash)

        text = opts[:msg].to_s
        text = text.gsub(/\e\[[0-9;]*m/, '')
        text = sanitize_debug_text(text: text)
        return if text.strip.empty?

        begin
          io = @debug_file
          return if io.nil? || (io.respond_to?(:closed?) && io.closed?)

          io.write(text.end_with?("\n") ? text : "#{text}\n")
          io.flush
        rescue StandardError
          return
        end
        text
      end

      private_class_method def self.format_progress(opts = {})
        cap = if opts.key?(:cap)
                opts[:cap].to_i
              else
                4_000
              end
        msg = opts[:msg].to_s
        msg = msg.tr("\n", ' ') unless opts[:keep_newlines]
        msg = msg[0, cap] if cap.positive? && msg.length > cap
        which = opts[:which_self]
        who = if which.is_a?(Module)
                (which.name || which.to_s).to_s
              else
                which.to_s
              end
        ts = Time.now.strftime('%Y-%m-%d %H:%M:%S.%L%z')
        bits = ["[DEBUG #{ts}]"]
        bits << who unless who.empty?
        bits << msg unless msg.empty?
        sanitize_debug_text(text: bits.join(' '))
      end

      private_class_method def self.color_progress(opts = {})
        line = opts[:line].to_s
        "\e[35m#{line}\e[0m"
      end

      private_class_method def self.trace_module_name(opts = {})
        tp = opts[:tp]
        return '' unless tp

        mod = tp.self.is_a?(Module) ? tp.self : tp.defined_class
        name = if mod.respond_to?(:name) && mod.name
                 mod.name
               else
                 mod.to_s
               end
        name.to_s.sub(/\A#<Class:(.+?)>\z/, '\1')
      end

      private_class_method def self.secret_key?(opts = {})
        opts[:key].to_s.match?(SECRET_KEY_RX)
      end

      private_class_method def self.sanitize_debug_text(opts = {})
        text = opts[:text].to_s
        text = text.gsub(SECRET_VALUE_RX, '[REDACTED]')
        text.gsub(/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/m, '[REDACTED]')
      end

      private_class_method def self.inspect_debug(opts = {})
        val = opts[:value]
        key = opts[:key]
        return '[REDACTED]' if secret_key?(key: key)
        return format_debug_hash(hash: val) if val.is_a?(Hash)
        return '[REDACTED]' if val.is_a?(String) && val.match?(SECRET_VALUE_RX)

        raw = sanitize_debug_text(text: val.inspect)
        raw = "#{raw[0, DEBUG_VALUE_MAX]}…" if raw.length > DEBUG_VALUE_MAX
        raw
      rescue StandardError
        "#<#{val.class}>"
      end

      private_class_method def self.format_debug_hash(opts = {})
        hash = opts[:hash]
        return '{}' unless hash.is_a?(Hash)

        parts = hash.map do |k, v|
          "#{k}: #{inspect_debug(value: v, key: k)}"
        end
        "{#{parts.join(', ')}}"
      end

      private_class_method def self.trace_arguments(opts = {})
        tp = opts[:tp]
        return '' unless tp

        bind = tp.binding
        parts = []
        Array(tp.parameters).each do |kind, name|
          next if name.nil?
          next if %i[rest keyrest block].include?(kind)
          next unless bind.local_variable_defined?(name)

          val = bind.local_variable_get(name)
          if name == :opts && val.is_a?(Hash)
            rendered = format_debug_hash(hash: val)
            return rendered == '{}' ? '' : rendered
          end

          parts << "#{name}=#{inspect_debug(value: val, key: name)}"
        end
        out = parts.join(', ')
        out = "#{out[0, DEBUG_ARGS_MAX]}…" if out.length > DEBUG_ARGS_MAX
        out
      rescue StandardError
        ''
      end

      private_class_method def self.format_trace_call(opts = {})
        tp = opts[:tp]
        klass = trace_module_name(tp: tp)
        meth = tp.method_id
        args = trace_arguments(tp: tp)
        args.to_s.empty? ? "#{klass}.#{meth}" : "#{klass}.#{meth}(#{args})"
      end

      private_class_method def self.traceable?(opts = {})
        tp = opts[:tp]
        prefixes = opts[:prefixes] || DEFAULT_TRACE_PREFIXES
        name = trace_module_name(tp: tp)
        return false if name.empty?
        return false if TRACE_SKIP_PREFIXES.any? { |p| name.start_with?(p) }
        return false unless prefixes.any? { |p| name.start_with?(p) }
        return false if TRACE_SKIP_METHODS.include?(tp.method_id)

        true
      end

      public_class_method def self.start_trace!(opts = {})
        return @debug_tp if @debug_tp && opts.is_a?(Hash)

        prefixes = Array(opts[:prefixes] || DEFAULT_TRACE_PREFIXES).map(&:to_s)
        prefixes = DEFAULT_TRACE_PREFIXES if prefixes.empty?
        @debug_tp = TracePoint.new(:call) do |tp|
          next unless debug_enabled?
          next unless traceable?(tp: tp, prefixes: prefixes)

          progress(
            msg: format_trace_call(tp: tp),
            which_self: ''
          )
        rescue StandardError
          nil
        end
        @debug_tp.enable
        @debug_tp
      end

      public_class_method def self.stop_trace!(opts = {})
        return if opts[:skip]

        @debug_tp&.disable
        @debug_tp = nil
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
          logger = #{self}.append(
            level: 'required - log verbosity :debug|:error|:fatal|:info|:learning|:unknown|:warn',
            msg: 'required - message to log',
            which_self: 'required - pass in self object from module calling #{self}'
          )

          path = #{self}.start_debug(
            tee: $stdout,
            session_id: 'optional - pwn-ai session id'
          )
          #{self}.next_request_log!(session_id: 'optional')
          #{self}.progress(msg: 'stage', which_self: self)
          #{self}.finish_request_log!(iter: 1, tools_called: 0, engine_s: 0.2, final_chars: 12)
          #{self}.stop_debug
          # start_debug(trace: true) enables per-call TracePoint (opt-in)
        "
      end
    end
  end
end
