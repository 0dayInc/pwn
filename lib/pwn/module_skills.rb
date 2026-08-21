# frozen_string_literal: true

require 'fileutils'

module PWN
  # Generate and install one skill per PWN module, mirroring the constant
  # path under etc/default_skills/pwn (e.g. PWN::Plugins::TransparentBrowser
  # → pwn/plugins/transparent_browser/SKILL.md). refresh! rewrites the gem
  # tree when a module changes. install overwrites the operator copy so
  # `pwn setup --migrate` stays current.
  module ModuleSkills
    LIB_ROOT = __dir__
    GEM_SKILLS = File.expand_path('../../etc/default_skills/pwn', __dir__)

    public_class_method def self.enumerate(opts = {})
      lib = opts[:lib_root].to_s
      lib = File.expand_path('..', LIB_ROOT) if lib.empty?
      found = []
      paths = [File.join(lib, 'pwn.rb')] + Dir.glob(File.join(lib, 'pwn', '**', '*.rb'))
      paths.uniq.each do |path|
        next unless File.file?(path)

        found.concat(parse_file(path: path, lib_root: lib))
      end
      found.uniq { |h| h[:source] }
    end

    public_class_method def self.relpath(opts = {})
      src = opts[:source].to_s.sub(/\.rb\z/, '')
      return "#{src}/SKILL.md" unless src.empty?

      const = opts[:const].to_s
      parts = const.split('::').map { |p| snake(name: p) }
      parts.shift if parts.first == 'pwn'
      File.join('pwn', *parts, 'SKILL.md')
    end

    public_class_method def self.render(opts = {})
      rec = opts[:module] || opts
      const = rec[:const].to_s
      methods = Array(rec[:methods]).uniq
      src = rec[:source].to_s
      blurb = sanitize_text(text: rec[:blurb].to_s.gsub(/\s+/, ' ').strip)
      blurb = "Public API for #{const}." if blurb.empty?
      slug = const.downcase.tr(':', '-').gsub(/-+/, '-')
      list = methods.map { |m| "- `#{m}`" }
      list = ['- _(no public class methods parsed)_'] if list.empty?
      refs = Array(rec[:references])
      ref_block = if refs.empty?
                    ''
                  else
                    items = refs.map { |r| "- `references/#{r[:file]}` — #{r[:title]}" }
                    "\n## References\n\n#{items.join("\n")}\n"
                  end
      <<~MD
        ---
        name: #{slug}
        description: Drive #{const} from pwn_eval.
        license: MIT
        allowed-tools: [pwn, pwn_eval]
        metadata:
          bundled: true
          generated: true
          module: #{const}
          source: #{src}
        ---

        # #{const}

        #{blurb}

        ## When to use

        Call `#{const}` from `pwn_eval` when the task needs this module.
        Do not reimplement it in shell.

        ## Methodologies

        Generated from `#{src}`. Prefer the public class methods below.
        Class methods take `(opts = {})` and read `opts`.

        ## How to call

        ```ruby
        #{const}.help
        #{example_call(const: const, methods: methods)}
        ```

        ## Public methods

        #{list.join("\n")}
        #{ref_block}
        ## Source

        `#{src}`

        ## Verification

        `#{const}.respond_to?(:#{methods.first || 'help'})` after the
        module is loaded. Read the source for parameter names.
      MD
    end

    public_class_method def self.refresh!(opts = {})
      dest = opts[:dest].to_s
      dest = File.expand_path('../../etc/default_skills', __dir__) if dest.empty?
      dest = File.dirname(dest) if File.basename(dest) == 'pwn'
      lib = opts[:lib_root].to_s
      lib = File.expand_path('..', LIB_ROOT) if lib.empty?
      mods = enumerate(lib_root: lib)
      FileUtils.mkdir_p(File.join(dest, 'pwn'))
      written = []
      keep = {}
      mods.each do |rec|
        skill_path = skill_abs(dest: dest, module: rec)
        dir = File.dirname(skill_path)
        FileUtils.mkdir_p(dir)
        keep[skill_path] = true
        if preserved_skill?(path: skill_path)
          Dir.glob(File.join(dir, 'references', '*.md')).each { |p| keep[p] = true }
        else
          body = render(module: rec)
          prev = File.file?(skill_path) ? File.read(skill_path) : nil
          if prev != body
            File.write(skill_path, body)
            written << skill_path
          end
          write_references(dir: dir, rec: rec, keep: keep, written: written)
        end
      end
      removed = prune_orphans(root: File.join(dest, 'pwn'), keep: keep)
      { modules: mods.length, written: written, removed: removed, dest: dest }
    end

    public_class_method def self.install(opts = {})
      root = opts[:pwn_skills_path]
      root = PWN::Config.pwn_skills_path if root.to_s.empty? && defined?(PWN::Config)
      src = opts[:source].to_s
      src = GEM_SKILLS if src.empty?
      return [] unless root.to_s != '' && Dir.exist?(src)

      dest_root = File.join(root, 'pwn')
      FileUtils.mkdir_p(dest_root)
      copied = []
      keep = {}
      froms = Dir.glob(File.join(src, 'SKILL.md'))
      froms.concat(Dir.glob(File.join(src, '**', 'SKILL.md')))
      froms.concat(Dir.glob(File.join(src, '**', 'references', '*.md')))
      froms.uniq.each do |from|
        next unless File.file?(from)

        rel = from.delete_prefix("#{src}/")
        to = File.join(dest_root, rel)
        FileUtils.mkdir_p(File.dirname(to))
        body = File.read(from)
        prev = File.file?(to) ? File.read(to) : nil
        if prev != body
          File.write(to, body)
          copied << { name: "pwn/#{File.dirname(rel)}", path: to } if File.basename(from) == 'SKILL.md'
        end
        keep[to] = true
      end
      prune_orphans(root: dest_root, keep: keep)
      copied
    rescue StandardError => e
      warn "[PWN::ModuleSkills] install failed: #{e.class}: #{e.message}"
      []
    end

    private_class_method def self.preserved_skill?(opts = {})
      path = opts[:path].to_s
      return false unless File.file?(path)

      head = File.read(path, 800).to_s
      head.match?(/^\s*preserve:\s*true\s*$/m) || head.match?(/^\s*generated:\s*false\s*$/m)
    end

    private_class_method def self.skill_abs(opts = {})
      dest = opts[:dest].to_s
      dest = File.dirname(dest) if File.basename(dest) == 'pwn'
      rec = opts[:module] || opts
      rel = relpath(source: rec[:source], const: rec[:const] || opts[:const])
      File.join(dest, rel)
    end

    private_class_method def self.write_references(opts = {})
      dir = opts[:dir]
      rec = opts[:rec]
      keep = opts[:keep]
      written = opts[:written]
      refs = Array(rec[:references])
      ref_dir = File.join(dir, 'references')
      if refs.empty?
        FileUtils.rm_rf(ref_dir)
        return
      end

      FileUtils.mkdir_p(ref_dir)
      refs.each do |ref|
        path = File.join(ref_dir, ref[:file])
        body = sanitize_text(text: ref[:body].to_s)
        prev = File.file?(path) ? File.read(path) : nil
        if prev != body
          File.write(path, body)
          written << path
        end
        keep[path] = true
      end
    end

    private_class_method def self.parse_file(opts = {})
      path = opts[:path].to_s
      lib = opts[:lib_root].to_s
      src = path.sub(%r{\A#{Regexp.escape(lib)}/?}, '')
      raw = File.read(path)
      stack = []
      const = nil
      blurb = ''
      pending = []
      methods = []
      raw.each_line do |line|
        if line =~ /^\s*#\s?(.*)$/
          pending << Regexp.last_match(1).to_s
          next
        end
        if line =~ /^\s*module\s+([A-Z][\w:]*)/
          ident = Regexp.last_match(1)
          stack = ident.include?('::') ? ident.split('::') : (stack + [ident])
          const = stack.join('::')
          blurb = pending.join(' ').strip if blurb.empty?
          pending = []
          next
        end
        pending = []
        next if line =~ /^\s*private_class_method/

        if line =~ /def self\.(\w+)/
          meth = Regexp.last_match(1)
          methods << meth unless methods.include?(meth)
        end
      end
      return fallback_record(source: src, raw: raw) if const.to_s.empty? || !const.start_with?('PWN')

      [{
        const: const,
        methods: methods,
        source: src,
        blurb: blurb,
        references: extract_references(text: raw, const: const)
      }]
    rescue StandardError
      []
    end

    private_class_method def self.fallback_record(opts = {})
      src = opts[:source].to_s
      raw = opts[:raw].to_s
      parts = src.sub(/\.rb\z/, '').split('/').map { |p| camel(name: p) }
      parts[0] = 'PWN' if parts.first.to_s.casecmp('pwn').zero?
      const = parts.join('::')
      [{
        const: const,
        methods: [],
        source: src,
        blurb: '',
        references: extract_references(text: raw, const: const)
      }]
    end

    private_class_method def self.camel(opts = {})
      opts[:name].to_s.split(/[_-]/).map(&:capitalize).join
    end

    private_class_method def self.extract_references(opts = {})
      text = opts[:text].to_s
      const = opts[:const].to_s
      refs = []
      section = text[/section:\s*['"]([^'"]+)['"]/, 1]
      cwe_id = text[/cwe_id:\s*['"]?(\d+)/, 1]
      cwe_uri = text[%r{cwe_uri:\s*['"](https?://[^'"]+)['"]}, 1]
      nist = text[%r{nist_800_53_uri:\s*['"](https?://[^'"]+)['"]}, 1]
      if cwe_id || nist || section
        body = "# #{const} security references\n\n"
        body << "- Section: #{section}\n" if section
        body << "- CWE-#{cwe_id}: #{cwe_uri || "https://cwe.mitre.org/data/definitions/#{cwe_id}.html"}\n" if cwe_id
        body << "- NIST SP 800-53: #{nist}\n" if nist
        refs << { file: 'security.md', title: 'CWE / NIST mapping', body: body }
      end
      urls = text.scan(%r{https?://[^\s'")]+}).uniq
      urls.reject! { |u| u.match?(/hermes/i) }
      urls.reject! { |u| cwe_uri && u.start_with?(cwe_uri) }
      urls.reject! { |u| nist && u.start_with?(nist) }
      urls.reject! { |u| sensitive_url?(url: u) }
      unless urls.empty?
        body = "# #{const} source links\n\n"
        urls.each { |u| body << "- #{u}\n" }
        refs << { file: 'urls.md', title: 'URLs from source', body: sanitize_text(text: body) }
      end
      refs
    end

    private_class_method def self.sensitive_url?(opts = {})
      u = opts[:url].to_s
      return true if u.include?('@') && u.match?(%r{https?://[^/]*:})
      return true if u.match?(/[?&](token|key|code|secret|password|passwd|access_token|refresh_token|api_key)=/i)
      return true if u.match?(/\Afile:/)
      return true if u.include?('/home/')

      false
    end

    ARTIFACT_RX = %r{
      -----BEGIN\ [A-Z ]*PRIVATE\ KEY----- |
      Bearer\s+[A-Za-z0-9\-._~+/]+=* |
      \beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+ |
      \b(?:sk|rk|pk|xai|xox[baprs]|ghp|gho|ghu|ghs|ghr|glpat|AKIA|ASIA|ya29)[-_][A-Za-z0-9\-_]{8,} |
      «redacted:[^»]*» |
      \#\{[^\}]+\} |
      /home/[A-Za-z0-9._-]+
    }ix

    private_class_method def self.sanitize_text(opts = {})
      s = opts[:text].to_s.gsub(/hermes(?:-agent)?/i, 'agent')
      s = s.gsub(ARTIFACT_RX, '[redacted]')
      s.gsub(/\b(personal_access_token|api_key|client_secret|refresh_token|bearer_token|access_token)\s*[:=]\s*\S+/i, '\1: [set in pwn-vault]')
    end

    private_class_method def self.snake(opts = {})
      opts[:name].to_s
                 .gsub(/([A-Z\d]+)([A-Z][a-z])/, '\1_\2')
                 .gsub(/([a-z\d])([A-Z])/, '\1_\2')
                 .tr('-', '_')
                 .downcase
    end

    private_class_method def self.example_call(opts = {})
      const = opts[:const]
      methods = Array(opts[:methods]) - %w[help authors]
      meth = methods.first || 'help'
      "#{const}.#{meth}(opts)"
    end

    private_class_method def self.prune_orphans(opts = {})
      root = opts[:root].to_s
      keep = opts[:keep]
      return [] unless Dir.exist?(root)

      removed = []
      Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).each do |path|
        next unless File.file?(path)
        next if File.basename(path).start_with?('.')
        next if keep[path]

        FileUtils.rm_f(path)
        removed << path
      end
      Dir.glob(File.join(root, '**', '*')).select { |p| File.directory?(p) }
         .sort_by(&:length).reverse_each do |dir|
        FileUtils.rmdir(dir) if Dir.empty?(dir)
      end
      removed
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts <<~USAGE
        USAGE:
          #{self}.enumerate
          #{self}.refresh!
          #{self}.install(pwn_skills_path: '~/.pwn/skills')
          #{self}.authors
      USAGE
    end
  end
end
