# frozen_string_literal: true

require 'digest'
require 'time'

module PWN
  # Read-only deployment diagnostics. A disk observation at compilation is not
  # an attestation of VM bytecode, native extensions, or later monkey patches.
  module RuntimeFingerprint
    OBSERVING_SINCE = Time.now.utc.iso8601(6).freeze
    ROOT = File.expand_path('..', __dir__).freeze
    OBSERVATIONS = {} # rubocop:disable Style/MutableConstant -- compile observations guarded by LOCK
    LOCK = Mutex.new
    TRACE = TracePoint.new(:script_compiled) do |event|
      path = event.instruction_sequence&.absolute_path
      next unless path&.start_with?("#{ROOT}/pwn/")

      begin
        digest = Digest::SHA256.file(path).hexdigest
        LOCK.synchronize { OBSERVATIONS[path] = { sha256: digest, observed_at: Time.now.utc.iso8601(6) }.freeze }
      rescue SystemCallError
        # Missing/unreadable source is reported as unknown, never as current.
        nil
      end
    end
    TRACE.enable

    public_class_method def self.report(opts = {})
      expected_root = opts[:expected_root]
      observations = LOCK.synchronize { OBSERVATIONS.dup }
      paths = $LOADED_FEATURES.grep(%r{/pwn(?:/.*)?\.rb\z}).map { |path| File.expand_path(path) }.uniq.sort
      components = paths.map do |path|
        observed = observations[path]
        disk = begin
          Digest::SHA256.file(path).hexdigest
        rescue SystemCallError
          nil
        end
        state = if !disk
                  'missing_or_unreadable'
                elsif !observed
                  'unknown_loaded_digest'
                elsif observed[:sha256] != disk
                  'changed_since_compile_observation'
                else
                  'matches_compile_observation'
                end
        { path: path, compile_observation: observed, current_disk_sha256: disk, state: state }
      end
      mismatch = components.any? { |row| %w[changed_since_compile_observation missing_or_unreadable].include?(row[:state]) }
      root_mismatch = expected_root && paths.any? { |path| !path.start_with?("#{File.expand_path(expected_root)}/") }
      {
        schema: 'pwn-runtime-fingerprint-v1', pid: Process.pid,
        process_start: process_identity, observing_since: OBSERVING_SINCE,
        loaded_version: defined?(PWN::VERSION) ? PWN::VERSION : nil,
        activated_gem_root: Gem.loaded_specs['pwn']&.full_gem_path,
        components: components, restart_required: mismatch || root_mismatch == true,
        expected_root: expected_root, root_mismatch: root_mismatch == true,
        guarantee: 'Compile-time disk observations only; pre-observer loads, bytecode provenance and monkey patches are not attested.',
        recovery: 'Preserve request/session evidence. Rebuild/install the intended source, restart the process, and compare paths and digests before resuming. Never hot-reload a running request.'
      }
    end

    private_class_method def self.process_identity
      stat = File.read('/proc/self/stat').split(') ', 2).last.split
      { source: 'linux-proc', boot_id: File.read('/proc/sys/kernel/random/boot_id').strip, start_ticks: stat[19] }
    rescue SystemCallError
      { source: 'unavailable', start_ticks: nil }
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Inspect observed deployment state without loading configuration or changing files.
        #{self}.report(expected_root: 'optional - intended library root; defaults to no root comparison')
        # Display author information.
        #{self}.authors
      "
    end
  end
end
