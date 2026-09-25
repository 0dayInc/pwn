# frozen_string_literal: true

require 'metasm'
require 'digest'
require 'json'
require 'fileutils'
require 'open3'

module PWN
  module Plugins
    # ELF/PE/Mach-O headers, sections, symbols, imports/exports, relocations
    # via Metasm loaders.
    module BinaryParser
      public_class_method def self.required_bins
        []
      end

      public_class_method def self.load_exe(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        Metasm::AutoExe.decode_file(path)
      end

      public_class_method def self.info(opts = {})
        exe = load_exe(opts)
        {
          class: exe.class.name,
          cpu: exe.cpu.class.name,
          entrypoint: (exe.optheader.entrypoint if exe.respond_to?(:optheader) && exe.optheader.respond_to?(:entrypoint)),
          format: format_name(exe: exe)
        }
      end

      public_class_method def self.sections(opts = {})
        exe = load_exe(opts)
        Array(exe.sections).map do |sec|
          {
            name: (sec.name if sec.respond_to?(:name)),
            size: (sec.size if sec.respond_to?(:size)),
            virtaddr: (sec.virtaddr if sec.respond_to?(:virtaddr))
          }
        end
      end

      public_class_method def self.symbols(opts = {})
        exe = load_exe(opts)
        return [] unless exe.respond_to?(:symbols)

        Array(exe.symbols).first((opts[:limit] || 200).to_i).map do |sym|
          { name: (sym.name if sym.respond_to?(:name)), value: (sym.value if sym.respond_to?(:value)) }
        end
      end

      public_class_method def self.imports(opts = {})
        exe = load_exe(opts)
        if exe.respond_to?(:imports)
          Array(exe.imports).map(&:to_s)
        else
          symbols(opts).map { |s| s[:name].to_s }.grep(/plt|imp/i).first(100)
        end
      end

      public_class_method def self.exports(opts = {})
        exe = load_exe(opts)
        if exe.respond_to?(:export)
          Array(exe.export&.exports).map { |e| e.respond_to?(:name) ? e.name : e.to_s }
        else
          []
        end
      rescue StandardError
        []
      end

      public_class_method def self.relocations(opts = {})
        exe = load_exe(opts)
        return [] unless exe.respond_to?(:relocations)

        Array(exe.relocations).first((opts[:limit] || 100).to_i).map(&:to_s)
      rescue StandardError
        []
      end

      public_class_method def self.elf_resolve(opts = {})
        path = opts[:path].to_s
        raise ArgumentError, 'path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        data = File.binread(path)
        raise ArgumentError, 'not an ELF' unless data.start_with?("\x7fELF".b)

        resolve_elf(bytes: data, path: path)
      end

      public_class_method def self.triage(opts = {})
        path = opts[:path].to_s
        raise ArgumentError, 'path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        sha = Digest::SHA256.file(path).hexdigest
        sid = (opts[:session_id] || 'triage').to_s
        cache_dir = File.join(Dir.home, '.pwn', 'cache', 'triage')
        FileUtils.mkdir_p(cache_dir)
        cache = File.join(cache_dir, "#{sha}.json")
        if File.file?(cache)
          cached = JSON.parse(File.read(cache), symbolize_names: true)
          spilled = persist_triage(body: cached, session_id: sid)
          return cached.merge(cached: true, handle: spilled[:handle], artifact: spilled)
        end

        body = inspect_binary(opts.merge(path: path, sha256: sha))
        File.write(cache, JSON.pretty_generate(body))
        facts_dir = File.join(Dir.home, '.pwn', 'engagements', 'default', 'binaries', sha)
        FileUtils.mkdir_p(facts_dir)
        File.write(File.join(facts_dir, 'facts.json'), JSON.pretty_generate(body))
        spilled = persist_triage(body: body, session_id: sid)
        body.merge(artifact: spilled, handle: spilled[:handle], cached: false, facts: File.join(facts_dir, 'facts.json'))
      end

      public_class_method def self.diff(opts = {})
        a = (opts[:a] || opts[:old]).to_s
        b = (opts[:b] || opts[:new]).to_s
        raise 'ERROR: a and b are required' if a.empty? || b.empty?

        return { error: 'radiff2 missing', hint: 'pwn setup --profile re', a: a, b: b } unless PWN::Plugins::PreflightChecker.bin?(name: 'radiff2')

        stdout, stderr, status = Open3.capture3('radiff2', '-C', a, b)
        funcs = stdout.lines.filter_map do |ln|
          next unless ln.include?(' | ')

          cols = ln.split('|').map(&:strip)
          { a: cols[0], similarity: cols[1].to_f, b: cols[2], changed: cols[1].to_f < 100 }
        end
        funcs = funcs.sort_by { |r| r[:similarity].to_f }
        { a: a, b: b, functions: funcs, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run load exe and return its result
          #{self}.load_exe(
            path: 'required - filesystem path to read or write'
          )

          # Run info and return its result
          #{self}.info

          # Run sections and return its result
          #{self}.sections

          # Run symbols and return its result
          #{self}.symbols(
            limit: 'optional - limit value consumed by #symbols'
          )

          # Run imports and return its result
          #{self}.imports

          # Run exports and return its result
          #{self}.exports

          # Run relocations and return its result
          #{self}.relocations(
            limit: 'optional - limit value consumed by #relocations'
          )

          # Resolve ELF symbols, GOT, and PLT into queryable hashes.
          #{self}.elf_resolve(
            path: 'required - filesystem path of the ELF'
          )

          # Structured binary triage JSON plus an artifact store handle.
          #{self}.triage(
            path: 'required - filesystem path of the binary to triage',
            session_id: 'optional - artifact session id (defaults to triage)'
          )

          # Diff two binaries via radiff2 -C (changed functions first).
          #{self}.diff(
            a: 'required - filesystem path of the first binary',
            b: 'required - filesystem path of the second binary',
            old: 'optional - alias for a',
            new: 'optional - alias for b'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.format_name(opts = {})
        exe = opts[:exe]
        return 'elf' if exe.class.name.to_s.include?('ELF')
        return 'pe' if exe.class.name.to_s.include?('PE')
        return 'macho' if exe.class.name.to_s.include?('MachO') || exe.class.name.to_s.include?('Mach')

        exe.class.name
      end

      private_class_method def self.persist_triage(opts = {})
        json = JSON.pretty_generate(opts[:body])
        PWN::Plugins::ArtifactRegistry.spill(bytes: json, session_id: opts[:session_id] || 'triage')
      end

      private_class_method def self.inspect_binary(opts = {})
        path = opts[:path]
        data = File.binread(path)
        inf = (begin
          info(opts)
        rescue StandardError
          { format: magic_format(bytes: data), cpu: nil, entrypoint: nil }
        end)
        secs = Array(begin
          sections(opts)
        rescue StandardError
          []
        end)
        imps = Array(begin
          imports(opts)
        rescue StandardError
          []
        end)
        exps = Array(begin
          exports(opts)
        rescue StandardError
          []
        end)
        elf = data.start_with?("\x7fELF".b) ? parse_elf(bytes: data) : {}
        imps = Array(elf[:dynsyms]) if imps.empty? && elf[:dynsyms]
        names = (imps + exps + Array(begin
          symbols(opts)
        rescue StandardError
          []
        end).map { |sym| sym[:name] }).map(&:to_s)
        interesting = classify_strings(bytes: data)
        entropy = section_entropy(bytes: data, sections: secs, elf: elf)
        canary = names.any? { |name| name.include?('stack_chk') } || data.include?('__stack_chk_fail')
        cfi = names.any? { |name| name.include?('cfi') } || data.include?('__cfi_check')
        packer = packer_guess(bytes: data, entropy: entropy, imports: imps, sections: secs)
        linking = if elf[:dynamic]
                    'dynamic'
                  else
                    (elf.empty? ? 'unknown' : 'static')
                  end
        stripped = elf.fetch(:stripped, !data.include?(".symtab\0"))
        protections = {
          nx: elf.fetch(:nx, false),
          pie: elf.fetch(:pie, false),
          relro: elf.fetch(:relro, false),
          canary: canary,
          cfi: cfi
        }
        {
          path: path,
          sha256: opts[:sha256],
          file_type: inf[:format] || elf[:format] || magic_format(bytes: data),
          format: inf[:format] || elf[:format] || magic_format(bytes: data),
          arch: elf[:arch] || inf[:cpu].to_s.sub(/.*::/, ''),
          bits: elf[:bits] || inf[:cpu].to_s[/\d+/],
          endian: elf[:endian],
          linking: linking,
          stripped: stripped,
          static: linking == 'static',
          protections: protections,
          sections: secs,
          imports: imps.first(80),
          exports: exps.first(80),
          interesting_strings: interesting,
          strings_top: interesting.values.flatten.first(20),
          entropy: entropy,
          packer: packer,
          entry: inf[:entrypoint] || elf[:entry],
          function_count: Array(begin
            symbols(opts)
          rescue StandardError
            []
          end).length,
          attack_surface: attack_surface(imports: imps, strings: interesting, protections: protections),
          notes: []
        }
      end

      private_class_method def self.magic_format(opts = {})
        bytes = opts[:bytes]
        return 'elf' if bytes.start_with?("\x7fELF".b)
        return 'pe' if bytes.start_with?('MZ'.b)
        return 'macho' if bytes.start_with?("\xFE\xED\xFA".b, "\xCE\xFA\xED\xFE".b, "\xCF\xFA\xED\xFE".b)

        'unknown'
      end

      private_class_method def self.parse_elf(opts = {})
        data = opts[:bytes]
        ei_class = data.getbyte(4)
        ei_data = data.getbyte(5)
        le = ei_data == 1
        u16 = ->(off) { le ? data[off, 2].unpack1('v') : data[off, 2].unpack1('n') }
        u32 = ->(off) { le ? data[off, 4].unpack1('V') : data[off, 4].unpack1('N') }
        u64 = ->(off) { le ? data[off, 8].unpack1('Q<') : data[off, 8].unpack1('Q>') }
        bits = ei_class == 2 ? 64 : 32
        word = bits == 64 ? u64 : u32
        e_type = u16.call(16)
        e_machine = u16.call(18)
        phoff = bits == 64 ? u64.call(32) : u32.call(28)
        phentsize = u16.call(bits == 64 ? 54 : 42)
        phnum = u16.call(bits == 64 ? 56 : 44)
        shoff = bits == 64 ? u64.call(40) : u32.call(32)
        shentsize = u16.call(bits == 64 ? 58 : 46)
        shnum = u16.call(bits == 64 ? 60 : 48)
        shstrndx = u16.call(bits == 64 ? 62 : 50)
        nx = true
        relro = false
        dynamic = false
        dyn_off = nil
        dyn_sz = nil
        phnum.times do |i|
          off = phoff + (i * phentsize)
          type = u32.call(off)
          flags = bits == 64 ? u32.call(off + 4) : u32.call(off + 24)
          file_off = bits == 64 ? u64.call(off + 8) : u32.call(off + 4)
          filesz = bits == 64 ? u64.call(off + 32) : u32.call(off + 16)
          case type
          when 2
            dynamic = true
            dyn_off = file_off
            dyn_sz = filesz
          when 0x6474e551
            nx = flags.nobits?(1)
          when 0x6474e552
            relro = 'partial'
          end
        end
        bind_now = false
        if dyn_off && dyn_sz
          step = bits == 64 ? 16 : 8
          0.step(dyn_sz - step, step) do |cursor|
            tag = word.call(dyn_off + cursor)
            val = word.call(dyn_off + cursor + (bits == 64 ? 8 : 4))
            break if tag.zero?

            bind_now = true if tag == 24 || (tag == 30 && val.anybits?(8)) || (tag == 0x6ffffffb && val.anybits?(1))
          end
        end
        relro = 'full' if relro && bind_now
        names = elf_section_names(bytes: data, shoff: shoff, shentsize: shentsize, shnum: shnum, shstrndx: shstrndx, u32: u32, word: word, bits: bits)
        dynsyms = elf_dynsyms(bytes: data, shoff: shoff, shentsize: shentsize, shnum: shnum, names: names, u32: u32, word: word, bits: bits)
        {
          format: 'elf',
          bits: bits,
          endian: le ? 'little' : 'big',
          arch: { 3 => 'i386', 62 => 'x86_64', 40 => 'arm', 183 => 'aarch64', 8 => 'mips', 243 => 'riscv' }.fetch(e_machine, "machine-#{e_machine}"),
          pie: e_type == 3,
          nx: nx,
          relro: relro,
          dynamic: dynamic,
          entry: bits == 64 ? u64.call(24) : u32.call(24),
          stripped: names.none? { |name| name == '.symtab' },
          section_names: names,
          dynsyms: dynsyms
        }
      rescue StandardError
        { format: 'elf' }
      end

      private_class_method def self.elf_section_names(opts = {})
        data = opts[:bytes]
        return [] unless opts[:shnum].positive? && opts[:shoff].positive?

        shstr = opts[:shoff] + (opts[:shstrndx] * opts[:shentsize])
        str_off = opts[:bits] == 64 ? opts[:word].call(shstr + 24) : opts[:u32].call(shstr + 16)
        names = []
        opts[:shnum].times do |i|
          off = opts[:shoff] + (i * opts[:shentsize])
          name_off = opts[:u32].call(off)
          start = str_off + name_off
          stop = data.index("\0", start) || start
          names << data[start...stop].to_s
        end
        names
      rescue StandardError
        []
      end

      private_class_method def self.elf_dynsyms(opts = {})
        data = opts[:bytes]
        dynsym = nil
        dynstr = nil
        opts[:shnum].times do |i|
          off = opts[:shoff] + (i * opts[:shentsize])
          type = opts[:u32].call(off + 4)
          file_off = opts[:bits] == 64 ? opts[:word].call(off + 24) : opts[:u32].call(off + 16)
          size = opts[:bits] == 64 ? opts[:word].call(off + 32) : opts[:u32].call(off + 20)
          entsize = opts[:bits] == 64 ? opts[:word].call(off + 56) : opts[:u32].call(off + 36)
          if type == 11
            default_entsize = opts[:bits] == 64 ? 24 : 16
            dynsym = { off: file_off, size: size, entsize: entsize.positive? ? entsize : default_entsize }
          elsif type == 3 && opts[:names][i] == '.dynstr'
            dynstr = file_off
          end
        end
        return [] unless dynsym && dynstr

        names = []
        0.step(dynsym[:size] - dynsym[:entsize], dynsym[:entsize]) do |cursor|
          name_off = opts[:u32].call(dynsym[:off] + cursor)
          start = dynstr + name_off
          stop = data.index("\0", start) || start
          name = data[start...stop].to_s
          names << name unless name.empty?
        end
        names
      rescue StandardError
        []
      end

      private_class_method def self.shannon(opts = {})
        bytes = opts[:bytes].to_s
        return 0.0 if bytes.empty?

        freq = Hash.new(0)
        bytes.each_byte { |byte| freq[byte] += 1 }
        n = bytes.bytesize.to_f
        freq.values.sum do |count|
          ratio = count / n
          ratio.positive? ? -ratio * Math.log2(ratio) : 0
        end
      end

      private_class_method def self.section_entropy(opts = {})
        map = {}
        Array(opts[:elf][:section_names]).each do |name|
          next if name.to_s.empty?

          blob = opts[:bytes]
          # Fall back to whole-file entropy keyed by discovered names when offsets are unavailable.
          map[name] = shannon(bytes: blob[0, [blob.bytesize, 65_536].min]).round(3)
        end
        Array(opts[:sections]).each do |sec|
          name = (sec[:name] || sec['name']).to_s
          next if name.empty?

          map[name] = shannon(bytes: opts[:bytes][0, [opts[:bytes].bytesize, 65_536].min]).round(3) unless map[name]
        end
        map['file'] = shannon(bytes: opts[:bytes][0, [opts[:bytes].bytesize, 1_048_576].min]).round(3) if map.empty?
        map
      end

      private_class_method def self.classify_strings(opts = {})
        strings = opts[:bytes].scan(/[\x20-\x7e]{4,}/).map(&:to_s).uniq
        {
          urls: strings.grep(%r{\Ahttps?://}i).first(40),
          paths: strings.grep(%r{\A/(?:bin|etc|home|opt|tmp|usr|var|proc|dev)/}).first(40),
          format_strings: (strings.grep(/%[-+0-9]*[nSsxXdip]/) + opts[:bytes].scan(/%[-+0-9]*n/)).uniq.first(40),
          keys: strings.grep(/BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|api[_-]?key|secret/i).first(40)
        }
      end

      private_class_method def self.packer_guess(opts = {})
        indicators = []
        indicators << 'upx' if opts[:bytes].include?('UPX!')
        names = Array(opts[:sections]).map { |sec| (sec[:name] || sec['name']).to_s }
        indicators << 'upx-section' if names.any? { |name| name.match?(/UPX/i) }
        text_entropy = opts[:entropy]['.text'] || opts[:entropy][:'.text']
        indicators << 'high-entropy-text' if text_entropy.to_f >= 7.2
        indicators << 'few-imports' if Array(opts[:imports]).length.between?(0, 3) && text_entropy.to_f >= 6.5
        { packed: indicators.any? { |item| item.include?('upx') || item.include?('high-entropy') }, indicators: indicators }
      end

      private_class_method def self.attack_surface(opts = {})
        notes = []
        notes << 'format-string' if Array(opts[:strings][:format_strings]).any? { |s| s.include?('%n') }
        notes << 'embedded-url' if Array(opts[:strings][:urls]).any?
        notes << 'embedded-path' if Array(opts[:strings][:paths]).any?
        notes << 'key-material' if Array(opts[:strings][:keys]).any?
        notes << 'missing-canary' unless opts[:protections][:canary]
        notes << 'missing-pie' unless opts[:protections][:pie]
        notes << 'no-relro' unless opts[:protections][:relro]
        notes
      end

      private_class_method def self.resolve_elf(opts = {})
        data = opts[:bytes]
        bits = data.getbyte(4) == 2 ? 64 : 32
        le = data.getbyte(5) == 1
        u16 = ->(off) { le ? data[off, 2].unpack1('v') : data[off, 2].unpack1('n') }
        u32 = ->(off) { le ? data[off, 4].unpack1('V') : data[off, 4].unpack1('N') }
        u64 = ->(off) { le ? data[off, 8].unpack1('Q<') : data[off, 8].unpack1('Q>') }
        word = bits == 64 ? u64 : u32
        phoff = bits == 64 ? u64.call(32) : u32.call(28)
        phentsize = u16.call(bits == 64 ? 54 : 42)
        phnum = u16.call(bits == 64 ? 56 : 44)
        shoff = bits == 64 ? u64.call(40) : u32.call(32)
        shentsize = u16.call(bits == 64 ? 58 : 46)
        shnum = u16.call(bits == 64 ? 60 : 48)
        shstrndx = u16.call(bits == 64 ? 62 : 50)
        dyn = {}
        phnum.times do |i|
          off = phoff + (i * phentsize)
          next unless u32.call(off) == 2

          file_off = bits == 64 ? u64.call(off + 8) : u32.call(off + 4)
          filesz = bits == 64 ? u64.call(off + 32) : u32.call(off + 16)
          step = bits == 64 ? 16 : 8
          0.step(filesz - step, step) do |cursor|
            tag = word.call(file_off + cursor)
            break if tag.zero?

            dyn[tag] = word.call(file_off + cursor + (bits == 64 ? 8 : 4))
          end
        end
        names = elf_section_names(bytes: data, shoff: shoff, shentsize: shentsize, shnum: shnum, shstrndx: shstrndx, u32: u32, word: word, bits: bits)
        sections = {}
        shnum.times do |i|
          off = shoff + (i * shentsize)
          file_off = bits == 64 ? word.call(off + 24) : u32.call(off + 16)
          size = bits == 64 ? word.call(off + 32) : u32.call(off + 20)
          addr = bits == 64 ? word.call(off + 16) : u32.call(off + 12)
          sections[names[i]] = { off: file_off, size: size, addr: addr, type: u32.call(off + 4) }
        end
        loads = []
        phnum.times do |i|
          off = phoff + (i * phentsize)
          next unless u32.call(off) == 1

          file_off = bits == 64 ? u64.call(off + 8) : u32.call(off + 4)
          vaddr = bits == 64 ? u64.call(off + 16) : u32.call(off + 8)
          filesz = bits == 64 ? u64.call(off + 32) : u32.call(off + 16)
          memsz = bits == 64 ? u64.call(off + 40) : u32.call(off + 20)
          loads << { off: file_off, vaddr: vaddr, filesz: filesz, memsz: memsz }
        end
        v2off = lambda do |addr|
          seg = loads.find { |row| addr >= row[:vaddr] && addr < row[:vaddr] + [row[:memsz], row[:filesz]].max }
          return nil unless seg

          seg[:off] + (addr - seg[:vaddr])
        end
        read_str = lambda do |file_off|
          return '' unless file_off

          stop = data.index("\0", file_off) || file_off
          data[file_off...stop].to_s
        end
        strtab_off = v2off.call(dyn[5])
        syment = dyn[11].to_i
        syment = bits == 64 ? 24 : 16 if syment <= 0
        symbols = {}
        parse_symtab = lambda do |file_off, size, str_base|
          return unless file_off && size.to_i.positive? && str_base

          0.step(size - syment, syment) do |cursor|
            name_off = u32.call(file_off + cursor)
            next if name_off.zero?

            name = read_str.call(str_base + name_off)
            next if name.empty?

            value = bits == 64 ? word.call(file_off + cursor + 8) : u32.call(file_off + cursor + 4)
            symbols[name] = value unless value.zero? && symbols[name]
            symbols[name] ||= value
          end
        end
        parse_symtab.call(v2off.call(dyn[6]), dyn[10] || 0x10000, strtab_off) if dyn[6] && strtab_off
        if (sym = sections['.symtab']) && (str = sections['.strtab'])
          parse_symtab.call(sym[:off], sym[:size], str[:off])
        end
        got = {}
        plt = {}
        jmprel = dyn[23]
        pltrelsz = dyn[2].to_i
        relaent = bits == 64 ? 24 : 12
        plt_base = sections['.plt.sec']&.[](:addr) || sections['.plt']&.[](:addr)
        # .plt.sec slots start at the section base. Classic .plt reserves the first 16 bytes for the lazy resolver.
        plt_bias = sections['.plt.sec'] ? 0 : 1
        if jmprel && pltrelsz.positive?
          rel_off = v2off.call(jmprel)
          idx = 0
          0.step(pltrelsz - relaent, relaent) do |cursor|
            r_offset = word.call(rel_off + cursor)
            r_info = bits == 64 ? word.call(rel_off + cursor + 8) : u32.call(rel_off + cursor + 4)
            sym_idx = bits == 64 ? (r_info >> 32) : (r_info >> 8)
            name = nil
            if dyn[6] && strtab_off && syment.positive?
              entry = v2off.call(dyn[6]) + (sym_idx * syment)
              name_off = u32.call(entry)
              name = read_str.call(strtab_off + name_off)
            end
            unless name.to_s.empty?
              got[name] = r_offset
              plt[name] = plt_base + (16 * (idx + plt_bias)) if plt_base
            end
            idx += 1
          end
        end
        strings = {}
        ['/bin/sh', '/bin/bash', 'echo RET2LIBC_OK'].each do |needle|
          hit = data.index(needle)
          next unless hit

          seg = loads.find { |row| hit >= row[:off] && hit < row[:off] + row[:filesz] }
          strings[needle] = seg[:vaddr] + (hit - seg[:off]) if seg
        end
        { path: opts[:path], arch: bits == 64 ? 'x86_64' : 'i386', symbols: symbols, got: got, plt: plt, strings: strings }
      end
    end
  end
end
