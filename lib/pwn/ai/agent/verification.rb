# frozen_string_literal: true

require 'json'
require 'digest'
require 'open3'
require 'net/http'
require 'timeout'

module PWN
  module AI
    module Agent
      # Explicit host-owned acceptance checks, not a model-facing tool.
      module Verification
        public_class_method def self.run(opts = {})
          request = opts[:request].to_s
          requirements = Array(opts[:requirements]).map(&:to_s)
          raise ArgumentError, 'original request requirements required' if request.empty? || requirements.empty? || requirements.any? { |r| r.strip.empty? || !request.include?(r) } || requirements.uniq != requirements

          root = File.realpath(opts[:root].to_s)
          definitions = Array(opts[:checks])
          definitions.each do |check|
            raise ArgumentError, 'check must name a declared requirement' unless check.is_a?(Hash) && requirements.include?(check[:requirement])
          end

          # Commands may change artifacts. Inspect final bytes only after all
          # active checks have completed, regardless of contract list order.
          active, artifacts = definitions.partition { |check| !%w[file json].include?(check[:kind].to_s) }
          checks = (active + artifacts).map do |check|
            verify_check(opts.merge(check: check, root: root))
          end
          missing = requirements - checks.map { |check| check[:criterion] }
          status = if checks.any? { |check| check[:passed] == false }
                     :fail
                   elsif missing.any? || checks.any? { |check| check[:passed].nil? }
                     :unknown
                   else
                     :pass
                   end
          ids = checks.filter_map do |check|
            artifact = check[:artifact]
            next unless artifact && !check[:passed].nil?

            writer = Array(opts[:actions]).reverse.find { |action| action[:artifacts].is_a?(Hash) && action[:artifacts].key?(artifact[:path_digest]) }
            writer[:action_id] if writer && writer[:artifacts][artifact[:path_digest]] == artifact[:sha256]
          end.uniq
          spans = requirements.map { |requirement| { requirement: requirement, offset: request.index(requirement), length: requirement.length, sha256: Digest::SHA256.hexdigest(requirement) } }
          { runner_version: 1, request_digest: Digest::SHA256.hexdigest(request), requirements: requirements, requirement_spans: spans, missing: missing, checks: checks, status: status,
            attribution: { source: 'independent_verifier', verified_action_ids: ids } }
        end

        public_class_method def self.snapshot(opts = {})
          root = File.realpath(opts[:root].to_s)
          Array(opts[:checks]).each_with_object({}) do |check, artifacts|
            next unless %w[file json].include?(check[:kind].to_s)

            path = File.expand_path(check[:path].to_s, root)
            row = verify_check(root: root, check: check.merge(kind: :file, expected: nil))
            artifacts[Digest::SHA256.hexdigest(path)] = row.dig(:artifact, :sha256)
          end
        end

        private_class_method def self.verify_check(opts = {})
          check = opts[:check]
          row = { criterion: check[:requirement], passed: nil, evidence: 'unavailable' }
          return row.merge(command_check(opts)) if check[:kind].to_s == 'command'
          return row.merge(http_check(opts)) if check[:kind].to_s == 'http'
          return row.merge(answer_check(opts)) if check[:kind].to_s == 'answer'

          path = File.expand_path(check[:path].to_s, opts[:root])
          raise ArgumentError, 'artifact outside verification root' unless path.start_with?("#{opts[:root]}/")
          raise ArgumentError, 'unsupported verification check' unless %w[file json].include?(check[:kind].to_s)
          raise ArgumentError, 'expected content required' unless check.key?(:expected)
          return row.merge(passed: false, evidence: 'missing artifact') unless File.exist?(path) || File.symlink?(path)
          raise ArgumentError, 'artifact must be a regular in-root file' if File.symlink?(path) || !File.file?(path) || !File.realpath(path).start_with?("#{opts[:root]}/")

          bytes = File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
            # Validate the opened object, not a pathname that can be replaced.
            # Fail closed if the platform cannot resolve descriptor locations.
            location = File.realpath("/proc/self/fd/#{file.fileno}")
            raise ArgumentError, 'opened artifact outside verification root' unless location.start_with?("#{opts[:root]}/")
            raise ArgumentError, 'artifact must be a bounded regular file' unless file.stat.file? && file.stat.size <= 1_048_576

            data = file.read(1_048_577).to_s
            raise ArgumentError, 'artifact grew beyond limit' if data.bytesize > 1_048_576

            data
          end
          digest = Digest::SHA256.hexdigest(bytes)
          actual = check[:kind].to_s == 'json' ? JSON.parse(bytes) : bytes
          expected = check[:kind].to_s == 'json' ? JSON.parse(JSON.generate(check[:expected])) : check[:expected]
          row.merge(passed: actual == expected, evidence: digest, artifact: { path_digest: Digest::SHA256.hexdigest(path), sha256: digest })
        rescue JSON::ParserError
          row.merge(passed: false, evidence: 'invalid JSON artifact')
        rescue StandardError => e
          row.merge(error: e.class.to_s)
        end

        private_class_method def self.answer_check(opts = {})
          check = opts[:check]
          answer = opts.fetch(:answer)
          raise ArgumentError, 'literal expected answer required' unless check[:expected].is_a?(String) && answer.is_a?(String)

          sources = Array(check[:sources]).map do |source|
            quote = source.fetch(:quote)
            citation = source.fetch(:citation)
            raise ArgumentError, 'nonempty source quote and citation required' if quote.to_s.empty? || citation.to_s.empty?

            observed = verify_check(opts.merge(check: source.merge(kind: :file, requirement: check[:requirement])))
            supported = observed[:passed] == true && source.fetch(:expected).include?(quote) && answer.include?(quote) && answer.include?(citation)
            observed.merge(passed: supported)
          end
          result = { passed: answer == check[:expected] && sources.all? { |source| source[:passed] == true },
                     evidence: Digest::SHA256.hexdigest(answer), sources: sources }
          record_observation(opts.merge(result: result, locator: 'final_answer'))
          result
        end

        private_class_method def self.command_check(opts = {})
          raise ArgumentError, 'commands require explicit opt-in' unless opts[:allow_commands] == true

          check = opts[:check]
          argv = check[:argv]
          raise ArgumentError, 'literal argv required' unless argv.is_a?(Array) && !argv.empty? && argv.all? { |arg| arg.is_a?(String) && !arg.include?("\0") }

          timeout = (opts[:timeout] || 10).to_f.clamp(0.05, 60)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          output = {}
          status = nil
          Open3.popen3({ 'HOME' => opts[:root], 'PATH' => ENV.fetch('PATH', '') }, [argv.first, argv.first], *argv.drop(1), chdir: opts[:root], pgroup: true, unsetenv_others: true) do |stdin, stdout, stderr, waiter|
            stdin.close
            output = { stdout => +'', stderr => +'' }
            streams = output.keys
            begin
              until streams.empty?
                remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
                raise Timeout::Error if remaining <= 0

                ready = IO.select(streams, nil, nil, remaining)
                raise Timeout::Error unless ready

                ready.first.each do |stream|
                  data = stream.read_nonblock(4096, exception: false)
                  if data.nil?
                    streams.delete(stream)
                  elsif data != :wait_readable
                    output[stream] << data
                    raise IOError, 'verification output too large' if output[stream].bytesize > 1_048_576
                  end
                end
              end
              remaining = [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0].max
              raise Timeout::Error unless waiter.join(remaining)

              status = waiter.value
            ensure
              # A reaped leader does not imply its process group is empty.
              begin
                Process.kill('KILL', -waiter.pid)
              rescue Errno::ESRCH
                nil
              end
              waiter.join
            end
            text = output[stdout]
            result = { passed: status.exitstatus == check.fetch(:exit_code, 0) && (!check.key?(:expected) || text == check[:expected]),
                       evidence: Digest::SHA256.hexdigest(text), exit_code: status.exitstatus }
            record_observation(opts.merge(result: result, locator: Digest::SHA256.hexdigest(JSON.generate(argv))))
            return result
          end
        end

        private_class_method def self.http_check(opts = {})
          check = opts[:check]
          raise ArgumentError, 'URL must be explicitly allowed' unless Array(opts[:allowed_urls]).include?(check[:url])
          raise ArgumentError, 'expected response required' unless check.key?(:expected)

          uri = URI.parse(check[:url])
          raise ArgumentError, 'HTTP URL without credentials required' unless %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo

          timeout = (opts[:timeout] || 10).to_f.clamp(0.05, 60)
          text = +''
          response = nil
          Timeout.timeout(timeout) do
            Net::HTTP.start(uri.host, uri.port, nil, use_ssl: uri.scheme == 'https', open_timeout: timeout, read_timeout: timeout) do |http|
              http.request(Net::HTTP::Get.new(uri.request_uri)) do |res|
                response = res
                res.read_body do |chunk|
                  text << chunk
                  raise IOError, 'verification response too large' if text.bytesize > 1_048_576
                end
              end
            end
          end
          result = { passed: response.code.to_i == check.fetch(:status, 200) && text == check[:expected], evidence: Digest::SHA256.hexdigest(text), http_status: response.code.to_i }
          record_observation(opts.merge(result: result, locator: uri.to_s))
          result
        end

        private_class_method def self.record_observation(opts = {})
          runtime = Thread.current[:pwn_request_runtime]
          return unless runtime

          check = opts[:check]
          result = opts[:result]
          runtime.observe_evidence!(requirement: check[:requirement], kind: check[:kind], locator: opts[:locator],
                                    passed: result[:passed], sha256: result[:evidence], max_age: check[:max_age])
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Execute host-owned checks; coverage refers to explicit original-request clauses.
            #{self}.run(
              request: 'required - original request, unchanged',
              requirements: 'required - distinct verbatim request clauses to check',
              root: 'required - allowed artifact directory',
              checks: 'required - host-defined file/json/command/http/answer checks naming a requirement',
              answer: 'optional - actual final text for an answer check; expected text and cited file bytes are host-defined',
              allow_commands: 'optional - explicitly enable literal argv test commands (default false)',
              allowed_urls: 'optional - exact HTTP GET URLs permitted; redirects never followed',
              timeout: 'optional - per-command or HTTP timeout seconds (default 10, capped at 60)',
              actions: 'optional - host-observed action_id and changed artifact digest maps, never model claims'
            )
            # Capture declared artifact digests around an action for provenance.
            #{self}.snapshot(
              root: 'required - allowed artifact directory',
              checks: 'required - declared file/json checks'
            )
            # Display module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
