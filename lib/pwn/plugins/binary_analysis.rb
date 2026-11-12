# frozen_string_literal: true

require 'open3'
require 'digest'
require 'timeout'

module PWN
  module Plugins
    # Bounded, argv-only read-only backend shared by normalized analysis adapters.
    module BinaryAnalysis
      public_class_method def self.available?(opts = {})
        name = opts[:name]
        ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, name)) && !File.directory?(File.join(dir, name)) }
      end

      public_class_method def self.run(opts = {})
        argv = opts[:argv]
        timeout = opts.fetch(:timeout, 60)
        limit = opts.fetch(:limit, 2_000_000)
        output = +''
        Open3.popen2e([argv.first, argv.first], *argv.drop(1), pgroup: true) do |stdin, stream, waiter|
          stdin.close
          completed = false
          begin
            Timeout.timeout(timeout) do
              loop do
                output << stream.readpartial(16_384)
                raise 'binary backend output limit exceeded' if output.bytesize > limit
              rescue EOFError
                break
              end
              status = waiter.value
              completed = status.success?
              raise "backend exited #{status.exitstatus}: #{output[-1000, 1000] || output}" unless completed
            end
          ensure
            # The leader can exit while a same-group child still holds the pipe.
            # Signal the group on timeout, limit, or error. Do not reap descendants.
            unless completed
              begin
                Process.kill('KILL', -waiter.pid)
              rescue Errno::ESRCH, Errno::EPERM
                nil
              end
            end
            waiter.join if waiter.alive?
          end
        end
        output.encode('UTF-8', invalid: :replace, undef: :replace)
      end

      public_class_method def self.analyze(opts = {})
        path = File.realpath(File.expand_path(opts[:path].to_s))
        raise ArgumentError, 'binary must be a regular file' unless File.file?(path)

        result = { backend: 'binutils', status: 'degraded', risk_level: 'low', path: path, sha256: Digest::SHA256.file(path).hexdigest, functions: [], strings: [], imports: [], symbols: [], types: [], warnings: ['heavy analysis backend unavailable or binutils requested; no decompiled C or complete xrefs'] }
        { symbols: ['nm', '-a', path], imports: ['readelf', '--dyn-syms', '--wide', path], strings: ['strings', '-a', '-t', 'x', path], disassembly: ['objdump', '-d', path] }.each do |key, command|
          text = run(argv: command, timeout: opts.fetch(:timeout, 60))
          result[key] = case key
                        when :symbols
                          text.lines.filter_map do |line|
                            m = line.match(/^([0-9a-fA-F]+)\s+(\w)\s+(.+)$/)
                            { address: m[1].to_i(16), type: m[2], name: m[3] } if m
                          end
                        when :imports
                          text.lines.filter_map { |line| { name: line.split.last } if line.include?(' UND ') && line.split.length >= 8 }
                        when :strings
                          text.lines.filter_map do |line|
                            m = line.match(/^\s*([0-9a-f]+) (.*)$/)
                            { offset: m[1].to_i(16), string: m[2] } if m
                          end
                        else
                          text
                        end
        rescue StandardError => e
          result[:warnings] << "#{command.first}: #{e.message}"
        end
        result[:functions] = result.fetch(:disassembly, '').scan(/^([0-9a-fA-F]+) <([^>]+)>:/).map { |address, name| { address: address.to_i(16), name: name } }
        result
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Check whether a named backend executable is present on PATH.
          #{self}.available?(
            name: 'required - backend executable filename to search on PATH'
          )

          # Run a bounded argv subprocess without shell interpolation.
          #{self}.run(
            argv: 'required - array of executable name and separate argument strings',
            limit: 'optional - maximum captured subprocess output bytes before termination',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )

          # Read binary symbols, strings, imports and disassembly through binutils.
          #{self}.analyze(
            path: 'required - filesystem path to the local artifact or binary',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )

          # Display module authors.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
