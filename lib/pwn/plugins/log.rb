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

      # Open /tmp/pwn-ai-DEBUG-TIMESTAMP.log, tee the same lines to the TUI
      # (opts[:tee]), and TracePoint PWN modules that process a pwn-ai request.
      DEBUG_LOG_MAX = 1_024_000

      public_class_method def self.start_debug(opts = {})
        return @debug_path if debug_enabled? && opts.is_a?(Hash)

        ts = Time.now.strftime('%Y%m%d-%H%M%S')
        path = opts[:path].to_s
        path = "/tmp/pwn-ai-DEBUG-#{ts}.1.log" if path.empty?
        stem, idx = debug_path_parts(path: path)
        path = "#{stem}.#{idx}.log"
        FileUtils.mkdir_p(File.dirname(path))
        io = File.open(path, 'a')
        io.sync = true
        @debug_file = io
        @debug_path = path
        @debug_stem = stem
        @debug_index = idx
        @debug_tee = opts[:tee]
        @debug_tui_quiet = false
        @debug_enabled = true
        start_trace!(prefixes: opts[:prefixes]) unless opts[:trace] == false
        progress(msg: "debug session start path=#{path}", which_self: self)
        path
      end

      public_class_method def self.stop_debug(opts = {})
        reason = opts[:reason].to_s if opts.is_a?(Hash)
        if debug_enabled?
          tail = reason.to_s.empty? ? 'debug session stop' : "debug session stop reason=#{reason}"
          progress(msg: tail, which_self: self)
        end
        stop_trace!
        begin
          @debug_file&.close unless @debug_file.nil? || @debug_file.closed?
        rescue StandardError
          nil
        end
        path = @debug_path
        @debug_file = nil
        @debug_path = nil
        @debug_stem = nil
        @debug_index = nil
        @debug_tee = nil
        @debug_tui_quiet = false
        @debug_enabled = false
        path
      end

      private_class_method def self.debug_path_parts(opts = {})
        path = opts[:path].to_s
        return [Regexp.last_match(1), Regexp.last_match(2).to_i] if path =~ /\A(.+)\.(\d+)\.log\z/

        [path.sub(/\.log\z/, ''), 1]
      end

      private_class_method def self.roll_debug_log!(opts = {})
        return if opts[:skip]
        return if @debug_file.nil? || @debug_file.closed?
        return if @debug_file.size < DEBUG_LOG_MAX

        @debug_file.close
        @debug_index = @debug_index.to_i + 1
        path = "#{@debug_stem}.#{@debug_index}.log"
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
        line = format_progress(msg: msg, which_self: which)
        begin
          @debug_file&.puts(line)
          @debug_file&.flush
          roll_debug_log!
        rescue StandardError
          nil
        end
        tee = opts.key?(:tee) ? opts[:tee] : @debug_tee
        if !@debug_tui_quiet && tee.respond_to?(:puts)
          begin
            tee.puts(color_progress(line: line))
          rescue StandardError
            nil
          end
        end
        true
      ensure
        Thread.current[:pwn_log_progress] = false
      end

      private_class_method def self.format_progress(opts = {})
        msg = opts[:msg].to_s.tr("\n", ' ')[0, 4_000]
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
        "\001\e[35m\002#{line}\001\e[0m\002"
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
            path: 'optional - defaults to /tmp/pwn-ai-DEBUG-TIMESTAMP.log'
          )
          #{self}.progress(msg: 'stage', which_self: self)
          #{self}.stop_debug
        "
      end
    end
  end
end
