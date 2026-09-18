# frozen_string_literal: true

require 'open3'
require 'digest'
require 'json'
require 'fileutils'
require 'shellwords'
require 'rbconfig'
require 'base64'

module PWN
  module Plugins
    # AFL++ / libFuzzer campaign wrapper with corpus, dictionary, and RE triage handoff.
    module AFLplusplus
      public_class_method def self.required_bins
        %w[afl-fuzz]
      end

      public_class_method def self.fuzz(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'afl-fuzz')
        in_dir = opts[:in_dir] || opts[:corpus]
        out_dir = opts[:out_dir] || opts[:output]
        target = opts[:target]
        raise 'ERROR: in_dir, out_dir, and target are required' if in_dir.to_s.empty? || out_dir.to_s.empty? || target.to_s.empty?

        cmd = ['afl-fuzz', '-i', in_dir.to_s, '-o', out_dir.to_s, '--', target.to_s]
        cmd.concat(Array(opts[:args]))
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.parse_stats(opts = {})
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise 'ERROR: out_dir is required' if out_dir.empty?

        path = File.join(out_dir, 'fuzzer_stats')
        path = File.join(out_dir, 'default', 'fuzzer_stats') unless File.file?(path)
        return {} unless File.file?(path)

        File.read(path).each_line.with_object({}) do |line, acc|
          key, val = line.split(':', 2)
          next if key.to_s.strip.empty?

          acc[key.strip.to_sym] = val.to_s.strip
        end
      end

      public_class_method def self.dictionary_from_binary(opts = {})
        path = (opts[:path] || opts[:target] || opts[:bin]).to_s
        raise ArgumentError, 'path is required' if path.empty?

        triage = PWN::Plugins::BinaryParser.triage(path: path, session_id: opts[:session_id] || 'fuzz-dict')
        strings = triage[:interesting_strings] || {}
        tokens = []
        tokens.concat(Array(strings[:urls]))
        tokens.concat(Array(strings[:paths]))
        tokens.concat(Array(strings[:format_strings]))
        tokens.concat(Array(strings[:keys]))
        tokens.concat(Array(triage[:imports]).map(&:to_s).grep(/\A[A-Za-z_]{3,}/).first(20))
        tokens = tokens.map(&:to_s).uniq.reject(&:empty?).first(200)
        quoted = tokens.map { |token| format('"%s"', token.gsub('\\', '\\\\').gsub('"', '\\"')) }
        { path: path, tokens: tokens, dict: quoted.join("\n") }
      end

      public_class_method def self.prepare_corpus(opts = {})
        in_dir = (opts[:in_dir] || opts[:corpus]).to_s
        raise ArgumentError, 'in_dir is required' if in_dir.empty?

        FileUtils.mkdir_p(in_dir)
        File.binwrite(File.join(in_dir, 'seed'), "A\n") unless Dir.children(in_dir).any? { |name| File.file?(File.join(in_dir, name)) }
        Array(opts[:seeds]).each_with_index do |seed, idx|
          FileUtils.cp(seed, File.join(in_dir, "seed-#{idx}")) if File.file?(seed.to_s)
        end
        in_dir
      end

      public_class_method def self.campaign_command(opts = {})
        payload = {
          engine: opts[:engine] || 'aflplusplus',
          in_dir: opts[:in_dir],
          out_dir: opts[:out_dir],
          target: opts[:target],
          max_runtime: opts[:max_runtime],
          cwd: opts[:cwd],
          env: opts[:env],
          handoff: opts.fetch(:handoff, true)
        }
        b64 = Base64.strict_encode64(JSON.generate(payload))
        Shellwords.join(
          [
            RbConfig.ruby,
            '-rpwn',
            '-rjson',
            '-rbase64',
            '-e',
            'PWN::Plugins::AFLplusplus.campaign(JSON.parse(Base64.decode64(ARGV[0]), symbolize_names: true))',
            b64
          ]
        )
      end

      public_class_method def self.campaign(opts = {})
        opts = opts.transform_keys(&:to_sym)
        in_dir = prepare_corpus(opts)
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise ArgumentError, 'out_dir is required' if out_dir.empty?

        FileUtils.mkdir_p(out_dir)
        bin = binary_from_target(target: opts[:target])
        dict_info = File.file?(bin.to_s) ? dictionary_from_binary(path: bin) : { dict: '', tokens: [] }
        dict_path = File.join(out_dir, 'tokens.dict')
        File.write(dict_path, dict_info[:dict].to_s)
        unless opts[:skip_fuzz]
          argv = fuzzer_argv(opts.merge(in_dir: in_dir, dict: dict_path, binary: bin, out_dir: out_dir))
          run_fuzzer(argv: argv, max_runtime: opts[:max_runtime], env: opts[:env], cwd: opts[:cwd])
        end
        crash_triage(out_dir: out_dir, target: bin || opts[:target], handoff: opts.fetch(:handoff, true))
      end

      public_class_method def self.crash_triage(opts = {})
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise 'ERROR: out_dir is required' if out_dir.empty?

        files = crash_files(out_dir: out_dir)
        target = binary_from_target(target: opts[:target])
        groups = Hash.new { |hash, key| hash[key] = { files: [] } }
        files.each do |path|
          stdin = File.binread(path)
          crash = replay_crash(target: target, stdin: stdin)
          key = backtrace_hash(crash: crash)
          groups[key][:files] << path
          groups[key][:crash] ||= crash
          groups[key][:stdin] ||= stdin
        end
        triaged = []
        if opts[:handoff] != false
          groups.each do |key, group|
            triaged << handoff_re003(target: target, crash: group[:crash], stdin: group[:stdin], files: group[:files], backtrace_hash: key)
          end
        end
        hashes = files.map { |path| [path, Digest::SHA256.file(path).hexdigest] }
        {
          crashes: files,
          unique: groups.keys,
          triaged: triaged,
          pipeline: 'pwn-re-003',
          asan: files.any? { |path| File.binread(path).include?('AddressSanitizer') },
          artifacts: hashes.map { |path, sha| { path: path, sha256: sha } }
        }
      end

      public_class_method def self.minimize(opts = {})
        crash = opts[:crash].to_s
        out = opts[:out].to_s
        target = opts[:target].to_s
        raise 'ERROR: crash, out, and target are required' if crash.empty? || out.empty? || target.empty?
        return { error: 'afl-tmin missing', hint: 'pwn setup --profile re' } unless PWN::Plugins::PreflightChecker.bin?(name: 'afl-tmin')

        stdout, stderr, status = Open3.capture3('afl-tmin', '-i', crash, '-o', out, '--', target)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus, out: out }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run fuzz and return its result
          #{self}.fuzz(
            in_dir: 'required - in dir value consumed by #fuzz (defaults to opts[:corpus])',
            corpus: 'optional - corpus value consumed by #fuzz',
            out_dir: 'required - out dir value consumed by #fuzz (defaults to opts[:output])',
            output: 'optional - output value consumed by #fuzz',
            target: 'required - hostname, IP, or CIDR to scan',
            args: 'optional - Array args value consumed by #fuzz'
          )

          # Parse AFL fuzzer_stats (execs_per_sec, paths, crashes) from out_dir.
          #{self}.parse_stats(
            out_dir: 'required - AFL output directory containing fuzzer_stats',
            output: 'optional - alias for out_dir'
          )

          # Build an AFL/libFuzzer dictionary from interesting strings in a binary.
          #{self}.dictionary_from_binary(
            path: 'required - filesystem path of the fuzz target ELF',
            target: 'optional - alias for path',
            bin: 'optional - alias for path',
            session_id: 'optional - artifact session id for BinaryParser.triage'
          )

          # Ensure a corpus directory exists and contains at least one seed.
          #{self}.prepare_corpus(
            in_dir: 'required - corpus directory (defaults to opts[:corpus])',
            corpus: 'optional - alias for in_dir',
            seeds: 'optional - extra seed file paths to copy into the corpus'
          )

          # Build a durable Jobs command that runs campaign then RE triage.
          #{self}.campaign_command(
            engine: 'optional - aflplusplus or libfuzzer (defaults to aflplusplus)',
            in_dir: 'required - corpus directory',
            out_dir: 'required - fuzzer output directory',
            target: 'required - fuzz target command or binary path',
            max_runtime: 'optional - seconds the supervisor may run',
            cwd: 'optional - working directory',
            env: 'optional - string environment map',
            handoff: 'optional - false skips PWN-RE-003 crash handoff (defaults to true)'
          )

          # Prepare corpus/dict, run AFL++ or libFuzzer, then triage unique crashes.
          #{self}.campaign(
            engine: 'optional - aflplusplus or libfuzzer (defaults to aflplusplus)',
            in_dir: 'required - corpus directory',
            out_dir: 'required - fuzzer output directory',
            output: 'optional - alias for out_dir',
            target: 'required - fuzz target command or binary path',
            max_runtime: 'optional - seconds forwarded to the fuzzer',
            cwd: 'optional - working directory',
            env: 'optional - string environment map',
            skip_fuzz: 'optional - true harvests existing crashes without launching a fuzzer',
            handoff: 'optional - false skips PWN-RE-003 crash handoff (defaults to true)',
            seeds: 'optional - extra seed file paths to copy into the corpus'
          )

          # Dedup crashes by backtrace hash and hand unique ones to PWN-RE-003 triage.
          #{self}.crash_triage(
            out_dir: 'required - AFL output directory containing crashes/',
            output: 'optional - alias for out_dir',
            target: 'optional - fuzz target binary used to replay crashes',
            handoff: 'optional - false skips GDBMI/BinaryParser/ExploitDev handoff (defaults to true)'
          )

          # Minimize a crash input with afl-tmin when present.
          #{self}.minimize(
            crash: 'required - path to a crashing input',
            out: 'required - path to write the minimized input',
            target: 'required - fuzz target binary'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.binary_from_target(opts = {})
        parts = begin
          Shellwords.split(opts[:target].to_s)
        rescue ArgumentError
          [opts[:target].to_s]
        end
        parts.find { |part| part != '@@' && !part.start_with?('-') } || parts.first
      end

      private_class_method def self.fuzzer_argv(opts = {})
        engine = (opts[:engine] || 'aflplusplus').to_s
        if engine.downcase.include?('libfuzzer')
          argv = [opts[:binary] || binary_from_target(target: opts[:target])]
          argv << "-max_total_time=#{opts[:max_runtime].to_i}" if opts[:max_runtime].to_i.positive?
          argv << "-dict=#{opts[:dict]}" if opts[:dict].to_s != '' && File.file?(opts[:dict].to_s)
          argv << "-artifact_prefix=#{File.join(opts[:out_dir].to_s, 'crash-')}"
          argv << opts[:in_dir].to_s
        else
          argv = ['afl-fuzz', '-i', opts[:in_dir].to_s, '-o', opts[:out_dir].to_s]
          argv += ['-x', opts[:dict].to_s] if opts[:dict].to_s != '' && File.file?(opts[:dict].to_s)
          argv += ['--', *Shellwords.split(opts[:target].to_s)]
        end
        argv
      end

      private_class_method def self.run_fuzzer(opts = {})
        env = { 'AFL_NO_UI' => '1', 'AFL_SKIP_CPUFREQ' => '1', 'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES' => '1' }
        env.merge!(opts[:env].transform_keys(&:to_s)) if opts[:env].is_a?(Hash)
        kw = {}
        kw[:chdir] = opts[:cwd] if opts[:cwd].to_s != ''
        system(env, *opts[:argv], **kw)
      end

      private_class_method def self.crash_files(opts = {})
        out_dir = opts[:out_dir]
        files = Dir[File.join(out_dir, '**/crashes/id:*')]
        files += Dir[File.join(out_dir, 'crash-*')]
        files += Dir[File.join(out_dir, '**/crash-*')]
        files.select { |path| File.file?(path) && File.basename(path) != 'README.txt' }.uniq
      end

      private_class_method def self.replay_crash(opts = {})
        target = opts[:target].to_s
        stdin = opts[:stdin].to_s
        return dummy_crash(stdin: stdin) if target.empty?

        PWN::Plugins::GDBMI.run_to_crash(binary: target, stdin: stdin)
      rescue StandardError
        stdout, stderr, status = Open3.capture3(target, stdin_data: stdin)
        sig = status.termsig ? Signal.signame(status.termsig) : nil
        {
          signal: sig ? "SIG#{sig}" : 'UNKNOWN',
          pc: nil,
          fault_addr: nil,
          backtrace: stderr.lines.grep(/#\d+/).map(&:strip),
          stdout: stdout,
          stderr: stderr
        }
      end

      private_class_method def self.dummy_crash(opts = {})
        { signal: 'SIGSEGV', pc: Digest::SHA256.hexdigest(opts[:stdin].to_s)[0, 8], fault_addr: nil, backtrace: [] }
      end

      private_class_method def self.backtrace_hash(opts = {})
        crash = opts[:crash] || {}
        Digest::SHA256.hexdigest([crash[:signal], crash[:pc], crash[:fault_addr], Array(crash[:backtrace]).inspect].join('|'))[0, 16]
      end

      private_class_method def self.handoff_re003(opts = {})
        target = opts[:target].to_s
        crash = opts[:crash] || {}
        binary_triage = begin
          PWN::Plugins::BinaryParser.triage(path: target, session_id: 'pwn-re-003') if File.file?(target)
        rescue StandardError
          nil
        end
        exploitdev = begin
          PWN::Plugins::ExploitDev.from_crash(crash: crash, payload: opts[:stdin]) if crash.is_a?(Hash)
        rescue StandardError
          nil
        end
        {
          backtrace_hash: opts[:backtrace_hash],
          crash: crash,
          binary_triage: binary_triage,
          exploitdev: exploitdev,
          files: opts[:files],
          pipeline: 'pwn-re-003'
        }
      end
    end
  end
end
