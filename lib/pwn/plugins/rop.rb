# frozen_string_literal: true

require 'digest'
require 'pwn/plugins/binary_analysis'

module PWN
  module Plugins
    # Read-only gadget enumeration; clobbers are conservative syntactic estimates.
    module ROP
      public_class_method def self.required_bins
        %w[ROPgadget ropper objdump]
      end

      public_class_method def self.parse(opts = {})
        text = opts[:text].to_s
        _backend = opts[:backend]
        text.lines.filter_map do |line|
          match = line.match(/^\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})\s*:\s*(.+)$/)
          next unless match

          token = match[1]
          address = token.to_s.sub(/\A0x/i, '').to_i(16)
          gadget = match[2].strip.sub(/;\s*$/, '').gsub(/\s*;\s*/, '; ')
          annotate(row: { address: address, gadget: gadget })
        end
      end

      public_class_method def self.gadgets(opts = {})
        path = File.realpath(File.expand_path(opts[:path].to_s))
        backend = opts[:backend] || %w[ropper ROPgadget rp].find { |name| BinaryAnalysis.available?(name: name) } || 'scan'
        rows, status, warnings = collect_gadgets(path: path, backend: backend, timeout: opts.fetch(:timeout, 60))
        rows.each { |row| annotate(row: row) }
        {
          backend: backend,
          status: status,
          risk_level: 'low',
          path: path,
          sha256: Digest::SHA256.file(path).hexdigest,
          gadgets: filter(gadgets: rows, constraints: opts[:constraints] || {}),
          warnings: warnings
        }
      rescue StandardError => e
        raise if %w[scan objdump].include?(backend.to_s) || e.is_a?(ArgumentError)

        gadgets(opts.merge(backend: 'scan')).tap { |result| result[:warnings] << "#{backend}: #{e.message}" }
      end

      public_class_method def self.filter(opts = {})
        constraints = opts[:constraints] || {}
        constraints = constraints.transform_keys(&:to_sym)
        allowed = %i[contains max_instructions preserve min_address max_address]
        raise ArgumentError, "unsupported constraints: #{constraints.keys - allowed}" unless (constraints.keys - allowed).empty?

        Array(opts[:gadgets]).select do |row|
          preserved = Array(constraints[:preserve]).map { |register| canonical_register(register: register) }
          clobbered = Array(row[:regs_clobbered]).map { |register| canonical_register(register: register) }
          (!constraints[:contains] || row[:gadget].include?(constraints[:contains].to_s)) &&
            (!constraints[:max_instructions] || row[:gadget].split(';').length <= Integer(constraints[:max_instructions])) &&
            (preserved.empty? || (row[:clobbers_complete] && !preserved.intersect?(clobbered))) &&
            (!constraints[:min_address] || row[:address] >= Integer(constraints[:min_address])) &&
            (!constraints[:max_address] || row[:address] <= Integer(constraints[:max_address]))
        end
      end

      private_class_method def self.collect_gadgets(opts = {})
        backend = opts[:backend].to_s
        path = opts[:path]
        return [scan_elf(path: path), 'ok', ['native RX-section scan; not a complete semantic gadget search']] if backend == 'scan'

        command = case backend
                  when 'ROPgadget' then ['ROPgadget', '--binary', path, '--depth', '6']
                  when 'ropper' then ['ropper', '--file', path, '--nocolor', '--inst-count', '6']
                  when 'rp' then ['rp', '-f', path, '--unique']
                  when 'objdump' then ['objdump', '-d', '-M', 'intel', path]
                  else raise ArgumentError, 'unsupported gadget backend'
                  end
        text = BinaryAnalysis.run(argv: command, timeout: opts[:timeout])
        rows = if backend == 'objdump'
                 text.lines.filter_map do |line|
                   match = line.match(/^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(ret\w*\b.*)$/)
                   { address: match[1].to_i(16), gadget: match[2].strip } if match
                 end
               else
                 parse(text: text, backend: backend)
               end
        status = backend == 'objdump' ? 'degraded' : 'ok'
        warnings = if backend == 'objdump'
                     ['fallback enumerates aligned returns only, not a complete gadget search']
                   else
                     ['register clobbers are conservative estimates, not symbolic verification']
                   end
        [rows, status, warnings]
      end

      private_class_method def self.scan_elf(opts = {})
        data = File.binread(opts[:path])
        return [] unless data.start_with?("\x7fELF".b)

        bits = data.getbyte(4) == 2 ? 64 : 32
        le = data.getbyte(5) == 1
        u16 = ->(off) { le ? data[off, 2].unpack1('v') : data[off, 2].unpack1('n') }
        u32 = ->(off) { le ? data[off, 4].unpack1('V') : data[off, 4].unpack1('N') }
        u64 = ->(off) { le ? data[off, 8].unpack1('Q<') : data[off, 8].unpack1('Q>') }
        phoff = bits == 64 ? u64.call(32) : u32.call(28)
        phentsize = u16.call(bits == 64 ? 54 : 42)
        phnum = u16.call(bits == 64 ? 56 : 44)
        sigs = {
          "\x5f\xc3".b => 'pop rdi; ret',
          "\x5e\xc3".b => 'pop rsi; ret',
          "\x5a\xc3".b => 'pop rdx; ret',
          "\x58\xc3".b => 'pop rax; ret',
          "\x5b\xc3".b => 'pop rbx; ret',
          "\xc9\xc3".b => 'leave; ret',
          "\x90\xc3".b => 'nop; ret',
          "\xc3".b => 'ret'
        }
        rows = []
        phnum.times do |i|
          off = phoff + (i * phentsize)
          type = u32.call(off)
          next unless type == 1

          flags = bits == 64 ? u32.call(off + 4) : u32.call(off + 24)
          next unless flags.anybits?(1)

          file_off = bits == 64 ? u64.call(off + 8) : u32.call(off + 4)
          vaddr = bits == 64 ? u64.call(off + 16) : u32.call(off + 8)
          filesz = bits == 64 ? u64.call(off + 32) : u32.call(off + 16)
          slice = data[file_off, filesz].to_s
          sigs.each do |bytes, gadget|
            cursor = 0
            while (hit = slice.index(bytes, cursor))
              rows << { address: vaddr + hit, gadget: gadget }
              cursor = hit + 1
            end
          end
        end
        rows.uniq { |row| [row[:address], row[:gadget]] }
      end

      private_class_method def self.annotate(opts = {})
        row = opts[:row]
        regs = row[:gadget].downcase.scan(/\b(?:r(?:1[0-5]|[0-9])(?:d|w|b)?|[re]?(?:ax|bx|cx|dx|si|di|sp|bp)|[abcd][lh]|[xyz]mm\d+)\b/)
        regs += %w[rsp rip] if row[:gadget].match?(/\b(?:ret|pop|push|call)\b/)
        row[:regs_clobbered] = regs.uniq
        row[:clobbers_complete] = row[:gadget].split(';').all? { |ins| ins.strip.match?(/\A(?:pop\s+[a-z0-9]+|ret(?:\s+0x[0-9a-f]+)?|nop)\z/i) }
        row
      end

      private_class_method def self.canonical_register(opts = {})
        register = opts[:register]
        value = register.to_s.downcase
        families = { 'rax' => %w[rax eax ax al ah], 'rbx' => %w[rbx ebx bx bl bh], 'rcx' => %w[rcx ecx cx cl ch], 'rdx' => %w[rdx edx dx dl dh], 'rsi' => %w[rsi esi si sil], 'rdi' => %w[rdi edi di dil], 'rsp' => %w[rsp esp sp spl], 'rbp' => %w[rbp ebp bp bpl], 'rip' => %w[rip eip ip] }
        families.find { |_name, aliases| aliases.include?(value) }&.first || value.sub(/\A(r(?:[89]|1[0-5]))[dwb]\z/, '\\1')
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List expected analysis backend executables.
          #{self}.required_bins

          # Parse ropper, rp, or ROPgadget listings into queryable gadget records.
          #{self}.parse(
            text: 'required - raw gadget listing text',
            backend: 'optional - ropper|rp|ROPgadget (format hint only)'
          )

          # Enumerate read-only gadgets and conservatively filter register constraints.
          #{self}.gadgets(
            backend: 'optional - ropper|ROPgadget|rp|scan|objdump',
            constraints: 'optional - hash with contains, preserve register array, instruction and address bounds',
            path: 'required - filesystem path to the local artifact or binary',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )

          # Filter already enumerated gadget records with an explicit constraint set.
          #{self}.filter(
            constraints: 'optional - hash with contains, preserve register array, instruction and address bounds',
            gadgets: 'required - array of normalized gadget records returned by enumeration'
          )

          # Display module authors.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
