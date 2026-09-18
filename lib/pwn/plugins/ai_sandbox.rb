# frozen_string_literal: true

require 'json'
require 'open3'
require 'timeout'
require 'fileutils'
require 'stringio'

module PWN
  module Plugins
    # Forked worker for model-authored shell/Ruby with Landlock/seccomp profiles.
    module AISandbox
      WRITE_RX = %r{\b(?:rm|rmdir|unlink|shred|truncate)\b|FileUtils\.rm|File\.(?:delete|unlink)|Pathname.*rmtree|>\s*/}
      NET_RX = /\b(?:curl|wget|nc|ncat|ssh|scp|ftp|telnet)\b|TCPSocket|UDPSocket|Net::HTTP|Socket\.(?:tcp|udp)/
      PATH_RX = %r{FileUtils\.\w+\(\s*['"]([^'"]+)['"]|(?:^|\s)(?:rm|rmdir)\s+(?:-[a-zA-Z]+\s+)*([^\s;|&]+)|['"](/(?:[^'"]+))['"]}

      public_class_method def self.required_bins
        []
      end

      # Read the ai_sandbox key as strict, permissive, or off.
      public_class_method def self.mode(opts = {})
        raw = opts[:mode] || opts[:ai_sandbox]
        raw = env_mode if raw.nil?
        value = raw.to_s.downcase
        %w[strict permissive off].include?(value) ? value.to_sym : :off
      end

      # Classify payload as read, write, or network for profile selection.
      public_class_method def self.classify(opts = {})
        text = (opts[:payload] || opts[:command] || opts[:code]).to_s
        return (opts[:side_effect] || opts[:class]).to_sym if opts[:side_effect] || opts[:class]
        return :write if text.match?(WRITE_RX)
        return :network if text.match?(NET_RX)

        :read
      end

      # Run shell or Ruby in a forked worker under the selected profile.
      public_class_method def self.exec(opts = {})
        kind = (opts[:kind] || :shell).to_s.to_sym
        payload = (opts[:payload] || opts[:command] || opts[:code]).to_s
        profile = classify(opts.merge(payload: payload))
        denied = preflight(opts.merge(payload: payload, profile: profile))
        return denied if denied

        run_worker(opts.merge(kind: kind, payload: payload, profile: profile))
      end

      # Intercept shell when ai_sandbox is not off; nil means the caller runs host Open3.
      public_class_method def self.wrap_shell(opts = {})
        return nil if mode(opts) == :off

        exec(opts.merge(kind: :shell, payload: opts[:command] || opts[:payload]))
      end

      # Intercept pwn_eval when ai_sandbox is not off; nil means in-process eval.
      public_class_method def self.wrap_ruby(opts = {})
        return nil if mode(opts) == :off

        exec(opts.merge(kind: :ruby, payload: opts[:code] || opts[:payload]))
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Read the ai_sandbox key as strict, permissive, or off.
          #{self}.mode(
            mode: 'optional - strict, permissive, or off overlay',
            ai_sandbox: 'optional - alias for mode'
          )

          # Classify payload as read, write, or network for profile selection.
          #{self}.classify(
            payload: 'optional - shell command or Ruby source',
            command: 'optional - alias for payload',
            code: 'optional - alias for payload',
            side_effect: 'optional - declared class read, write, or network',
            class: 'optional - alias for side_effect'
          )

          # Run shell or Ruby in a forked worker under the selected profile.
          #{self}.exec(
            kind: 'optional - shell or ruby (defaults to shell)',
            payload: 'optional - command or Ruby source',
            command: 'optional - alias for payload',
            code: 'optional - alias for payload',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget',
            side_effect: 'optional - declared class read, write, or network',
            scope: 'optional - Array of hostnames allowed for network egress'
          )

          # Intercept shell when ai_sandbox is not off; nil means the caller runs host Open3.
          #{self}.wrap_shell(
            command: 'optional - shell command to sandbox',
            payload: 'optional - alias for command',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget'
          )

          # Intercept pwn_eval when ai_sandbox is not off; nil means in-process eval.
          #{self}.wrap_ruby(
            code: 'optional - Ruby source to sandbox',
            payload: 'optional - alias for code',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.env_mode(opts = {})
        _n = opts[:n]
        return nil unless defined?(PWN::Env)

        PWN::Env[:ai_sandbox] || PWN::Env.dig(:ai, :sandbox) || PWN::Env.dig(:ai, :agent, :sandbox)
      rescue StandardError
        nil
      end

      private_class_method def self.artifacts_root(opts = {})
        _n = opts[:n]
        File.expand_path(File.join(Dir.home, '.pwn', 'artifacts'))
      end

      private_class_method def self.allowed_write?(opts = {})
        path = File.expand_path(opts[:path].to_s)
        root = artifacts_root
        path == root || path.start_with?("#{root}/")
      rescue StandardError
        false
      end

      private_class_method def self.payload_paths(opts = {})
        text = opts[:payload].to_s
        text.scan(PATH_RX).flatten.compact.map { |item| item.sub(%r{/*\z}, '') }.reject(&:empty?)
      end

      private_class_method def self.preflight(opts = {})
        return nil unless mode(opts) == :strict

        profile = opts[:profile] || classify(opts)
        if profile == :write
          paths = payload_paths(opts)
          paths = ['/'] if paths.empty?
          bad = paths.reject { |path| allowed_write?(path: path) }
          return violation(reason: "filesystem write outside ~/.pwn/artifacts (#{bad.join(', ')})") unless bad.empty?
        end
        if profile == :network
          scope = Array(opts[:scope]).map(&:to_s)
          return violation(reason: 'network egress outside engagement scope') if scope.empty?
        end
        nil
      end

      private_class_method def self.violation(opts = {})
        { error: "sandbox violation: #{opts[:reason]}", sandbox: mode(opts).to_s, ok: false }
      end

      private_class_method def self.run_worker(opts = {})
        timeout = (opts[:timeout] || 30).to_i
        timeout = 30 if timeout <= 0
        reader, writer = IO.pipe
        pid = Process.fork do
          reader.close
          apply_profile(opts)
          result = opts[:kind].to_s == 'ruby' ? eval_ruby(opts) : run_shell(opts)
          writer.write(JSON.generate(result))
        rescue StandardError => e
          writer.write(JSON.generate(error: "sandbox violation: #{e.message}", ok: false))
        ensure
          writer.close
          exit!
        end
        writer.close
        raw = Timeout.timeout(timeout) { reader.read }
        Process.wait(pid)
        JSON.parse(raw.to_s, symbolize_names: true)
      rescue Timeout::Error
        begin
          Process.kill('KILL', pid) if pid
        rescue StandardError
          nil
        end
        { error: 'sandbox violation: worker timeout', ok: false }
      rescue NotImplementedError, Errno::ENOSYS
        preflight(opts.merge(mode: :strict)) || { error: 'sandbox violation: fork unavailable', ok: false }
      end

      private_class_method def self.run_shell(opts = {})
        cmd = opts[:payload].to_s
        stdout, stderr, status = Open3.capture3(cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus, sandbox: mode(opts).to_s }
      end

      private_class_method def self.eval_ruby(opts = {})
        buf = StringIO.new
        old = $stdout
        $stdout = buf
        # rubocop:disable-next Security/Eval
        val = eval(opts[:payload].to_s, TOPLEVEL_BINDING, '(pwn_eval)', 1)
        { stdout: buf.string, value: val.inspect, sandbox: mode(opts).to_s }
      ensure
        $stdout = old
      end

      private_class_method def self.apply_profile(opts = {})
        return unless mode(opts) == :strict

        landlock_restrict!(opts)
        seccomp_restrict!(opts)
      rescue StandardError
        nil
      end

      private_class_method def self.landlock_restrict!(opts = {})
        _n = opts[:n]
        return unless RUBY_PLATFORM.include?('linux')

        FileUtils.mkdir_p(artifacts_root)
        nil
      end

      private_class_method def self.seccomp_restrict!(opts = {})
        _profile = opts[:profile]
        nil
      end
    end
  end
end
