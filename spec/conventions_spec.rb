# frozen_string_literal: true

require 'spec_helper'

# Global source-level conventions for every Ruby module under lib/pwn.
#
# These rules are enforced on the SOURCE TEXT (not via runtime
# introspection) because the conventions are about how the code is
# written, and `public_class_method def self.x` vs a bare `def self.x`
# produce identical method objects at runtime.
#
# Runs automatically via `rake` → `rake spec` (RSpec::Core::RakeTask
# globs spec/**/*_spec.rb).
#
# RULES
#   0. Every method on a PWN namespace *module* MUST be referenced via
#      `self.<method_name>`:
#        public_class_method def self.foo ...   OR
#        private_class_method def self.bar ...
#      A bare instance-style `def foo` at module scope fails. So does
#      `module_function` (it produces bare `def` bodies that the other
#      rules cannot see). Nested `class` instance methods and bodies
#      opened via class_eval / module_eval / `class <<` are exempt —
#      those are real objects (e.g. SDR::Decoder::*::Demod) or third-
#      party reopenings, not the PWN module API.
#
#   1. Module methods MUST be declared with an explicit visibility
#      decorator immediately preceding `def self.<name>`:
#        public_class_method def self.foo ...   OR
#        private_class_method def self.bar ...
#      A bare `def self.foo` (no decorator on the same line) fails.
#
#   2. Module methods that accept arguments MUST take exactly one
#      argument named `opts` with a `{}` default:
#        def self.foo(opts = {})
#      Anything else inside `(...)` fails. Zero-arg methods are fine.
#
#   3. Methods declared `(opts = {})` MUST consume opts in the body,
#      i.e. at least one `opts[...]` reference. (Sanity check that the
#      hash isn't declared-and-ignored.)
#
#   4. Every leaf module file MUST define `def self.help`.
#
#   5. Every leaf module file MUST define `def self.authors`.
#
#   6. Every public class method except `help` MUST appear in that
#      module's `help` method — including `authors`. Directly above each
#      method, `help` MUST print a brief purpose line (what the method
#      does). Methods that take `(opts = {})` MUST document each
#      `opts[:key]` they read as `required` or `optional` plus an
#      operator-usable description (what to pass, not just the key name)
#      — same shape as PWN::WWW::Google.help.
#
# A "leaf module file" is any file under lib/pwn/**/*.rb that opens at
# least one `module` block. Pure namespace/index files (autoload-only,
# no method bodies) are exempt from 4/5 via NAMESPACE_INDEX_FILES.
#
# A small explicit allowlist exists for files that are intentionally
# off-convention (e.g. vendored third-party code). KEEP THIS LIST SHORT
# — every entry must carry a one-line justification.

module PWNConventions
  ROOT = File.expand_path('..', __dir__)
  LIB  = File.join(ROOT, 'lib', 'pwn')

  # --------------------------------------------------------------------
  # ALLOWLISTS — every entry must have a comment explaining why.
  # --------------------------------------------------------------------

  # Files exempt from ALL rules. Vendored / generated / non-module code.
  GLOBAL_ALLOWLIST = [
    'lib/pwn/version.rb' # single VERSION constant; not a behaviour module
  ].freeze

  # Files exempt from rules 4 & 5 only. These are pure autoload index
  # namespaces (no behaviour of their own; .help returns constants.sort).
  NAMESPACE_INDEX_FILES = [].freeze

  # --------------------------------------------------------------------

  RB_FILES = Dir[File.join(LIB, '**', '*.rb')].reject do |f|
    rel = f.sub("#{ROOT}/", '')
    GLOBAL_ALLOWLIST.include?(rel)
  end.sort.freeze

  MODULE_FILES = RB_FILES.select { |f| File.read(f).match?(/^\s*module\s+\w/) }.freeze

  # Match every `def self.<name>` along with whatever (if anything)
  # immediately precedes it on the same source line.
  SELF_DEF_RE = /^([ \t]*)((?:public_class_method|private_class_method)\s+)?def self\.([a-z_][\w?!]*)(?:\(([^)]*)\))?/

  # Bare instance-style method definitions (`def foo` without `self.`).
  BARE_DEF_RE = /^[ \t]*def ([a-z_][\w?!]*)(?:\(([^)]*)\))?/

  # module_function turns subsequent bare defs into module functions and
  # hides them from SELF_DEF_RE — forbid it outright so rule 0 fires.
  MODULE_FUNCTION_RE = /^\s*module_function\b/

  # Openers that introduce a non-module method container (instance methods OK).
  # Includes DSL blocks such as Pry::Commands.create_command / Class.new
  # that open an anonymous class body with bare instance methods.
  CLASS_LIKE_OPEN_RE = /
    \Aclass\b
    | \.class_eval\b
    | \.module_eval\b
    | \Aclass_eval\b
    | \Amodule_eval\b
    | \Aclass\s*<<
    | \.create_command\b
    | \bClass\.new\b
    | \bStruct\.new\b
    | \bModule\.new\b
    | \bData\.define\b
  /x

  MODULE_OPEN_RE = /\Amodule\s+[A-Z]/

  module_function

  def line_indent(line)
    line[/^[ \t]*/].to_s.length
  end

  def scan_methods(path)
    src   = File.read(path)
    lines = src.lines
    out   = []
    lines.each_with_index do |line, idx|
      m = line.match(SELF_DEF_RE)
      next unless m

      out << {
        file: path,
        line: idx + 1,
        decorator: m[2]&.strip,
        name: m[3],
        arglist: m[4],
        body_excerpt: lines[(idx + 1)..(idx + 60)]&.join.to_s,
        method_body: method_body_excerpt(lines, idx)
      }
    end
    out
  end

  def method_body_excerpt(lines, idx)
    indent = lines[idx][/^[ \t]*/]
    buf = []
    ((idx + 1)...lines.length).each do |i|
      break if lines[i].match?(/^#{Regexp.escape(indent)}end\b/)

      buf << lines[i]
      break if buf.length >= 120
    end
    buf.join
  end

  # Module-level bare `def name` only. Nested class instance methods and
  # class_eval / module_eval reopenings are legitimate and not part of the
  # PWN module API contract. Track open containers by indent so a plain
  # `end` inside a method body never pops the enclosing class/module.
  def scan_bare_defs(path)
    stack = [] # [{ type: :module|:class, indent: Integer }, ...]
    out   = []
    File.readlines(path).each_with_index do |line, idx|
      stripped = line.strip
      next if stripped.empty? || stripped.start_with?('#')

      indent = line_indent(line)

      if stripped == 'end' || stripped.match?(/\Aend\b/)
        stack.pop while stack.any? && stack.last[:indent] >= indent
        next
      end

      if stripped.match?(MODULE_OPEN_RE) && !stripped.match?(/\bend\b/)
        stack.pop while stack.any? && stack.last[:indent] >= indent
        stack << { type: :module, indent: indent }
        next
      end

      if stripped.match?(CLASS_LIKE_OPEN_RE) && !stripped.match?(/\bend\b/)
        stack.pop while stack.any? && stack.last[:indent] >= indent
        stack << { type: :class, indent: indent }
        next
      end

      next if line.match?(SELF_DEF_RE)

      m = line.match(BARE_DEF_RE)
      next unless m

      container = stack.reverse.find { |frame| frame[:indent] < indent }
      next if container.nil?
      next if container[:type] == :class

      out << {
        file: path,
        line: idx + 1,
        name: m[1],
        arglist: m[2]
      }
    end
    out
  end

  def scan_module_function(path)
    out = []
    File.readlines(path).each_with_index do |line, idx|
      next if line.match?(/^\s*#/)
      next unless line.match?(MODULE_FUNCTION_RE)

      out << { file: path, line: idx + 1 }
    end
    out
  end

  ALL_METHODS = MODULE_FILES.flat_map { |f| scan_methods(f) }.freeze
  ALL_BARE_DEFS = MODULE_FILES.flat_map { |f| scan_bare_defs(f) }.freeze
  ALL_MODULE_FUNCTIONS = MODULE_FILES.flat_map { |f| scan_module_function(f) }.freeze

  HELP_SKIP = %w[help].freeze

  def help_text(path)
    lines = File.readlines(path)
    idx = lines.find_index { |l| l.match?(/def self\.help\b/) }
    return '' unless idx

    indent = lines[idx][/^[ \t]*/]
    buf = []
    ((idx + 1)...lines.length).each do |i|
      break if lines[i].match?(/^#{Regexp.escape(indent)}end\b/)

      buf << lines[i]
    end
    buf.join
  end

  def opts_keys(body)
    body.to_s.scan(/opts\[\s*:([A-Za-z_]\w*)\s*\]/).flatten.uniq
  end

  def thin_option_desc?(key, desc)
    rest = desc.to_s.strip.sub(/\A(?:required|optional)\s*-\s*/i, '')
    return true if rest.empty?

    norm = rest.downcase.gsub(/[^a-z0-9]+/, ' ').strip
    key_norm = key.to_s.downcase.tr('_', ' ')
    return true if norm == key_norm

    words = rest.split
    words.length < 2 && rest.length < 18
  end

  def purpose_above?(help, name)
    lines = help.to_s.lines
    idx = lines.find_index { |l| l.match?(/\#\{self\}\.#{Regexp.escape(name)}(?!\w)/) }
    return false unless idx

    prev = nil
    (idx - 1).downto(0) do |i|
      next if lines[i].strip.empty?

      prev = lines[i]
      break
    end
    return false unless prev

    text = prev.strip.sub(/\A#\s*/, '')
    return false if text.match?(/\AUSAGE:/i)
    return false if text.match?(/\.\w+\s*\(/) || text.match?(/\#\{self\}/)
    return false if text.match?(/\A\w+\s*=\s*PWN::/)
    return false if text.downcase.gsub(/[^a-z0-9]+/, ' ').strip == name.downcase.tr('_', ' ')

    words = text.split
    words.length >= 3 || text.length >= 20
  end

  def rel(path)
    path.sub("#{ROOT}/", '')
  end
end

describe 'PWN module conventions' do
  c = PWNConventions

  # ---------------------------------------------------------------- 0 --
  it '0) every PWN module method is referenced via `self.<method_name>` (no bare module-level `def`, no module_function)' do
    bare = c::ALL_BARE_DEFS
    mfun = c::ALL_MODULE_FUNCTIONS
    parts = []
    unless bare.empty?
      parts << 'bare module-level `def <name>` (use `public_class_method def self.<name>` / `private_class_method def self.<name>`):'
      parts.concat(bare.map { |m| "  #{c.rel(m[:file])}:#{m[:line]}  def #{m[:name]}" })
    end
    unless mfun.empty?
      parts << '`module_function` is forbidden (declare each method with def self.<name>):'
      parts.concat(mfun.map { |m| "  #{c.rel(m[:file])}:#{m[:line]}  module_function" })
    end
    msg = parts.join("\n")
    expect(bare + mfun).to be_empty, msg
  end

  # ---------------------------------------------------------------- 1 --
  it '1) every `def self.<name>` is decorated with public_class_method or private_class_method' do
    bare = c::ALL_METHODS.select { |m| m[:decorator].nil? }
    msg  = bare.map { |m| "  #{c.rel(m[:file])}:#{m[:line]}  def self.#{m[:name]}" }.join("\n")
    expect(bare).to be_empty, "bare `def self.*` (add public_class_method / private_class_method):\n#{msg}"
  end

  # ---------------------------------------------------------------- 2 --
  it '2) every argument-accepting module method takes exactly `(opts = {})`' do
    bad = c::ALL_METHODS.reject do |m|
      a = m[:arglist]
      a.nil? || a.strip.empty? || a.strip == 'opts = {}'
    end
    msg = bad.map { |m| "  #{c.rel(m[:file])}:#{m[:line]}  def self.#{m[:name]}(#{m[:arglist]})" }.join("\n")
    expect(bad).to be_empty, "non-conforming arglists (use `(opts = {})`):\n#{msg}"
  end

  # ---------------------------------------------------------------- 3 --
  it '3) methods declared `(opts = {})` actually consume opts in the body' do
    unused = c::ALL_METHODS.select do |m|
      m[:arglist]&.strip == 'opts = {}' &&
        !m[:body_excerpt].match?(/\bopts\s*\[|\bopts\.(?:dig|fetch|key\?|keys|values|merge|each|delete|map|\[\])/)
    end
    msg = unused.map { |m| "  #{c.rel(m[:file])}:#{m[:line]}  def self.#{m[:name]}(opts = {})  # opts never read" }.join("\n")
    expect(unused).to be_empty, "declared `(opts = {})` but never read opts (unpack at top of method):\n#{msg}"
  end

  # ---------------------------------------------------------------- 4 --
  it '4) every module file defines `def self.help`' do
    missing = c::MODULE_FILES.reject do |f|
      c::NAMESPACE_INDEX_FILES.include?(c.rel(f)) || File.read(f).match?(/def self\.help\b/)
    end
    msg = missing.map { |f| "  #{c.rel(f)}" }.join("\n")
    expect(missing).to be_empty, "modules missing `def self.help`:\n#{msg}"
  end

  # ---------------------------------------------------------------- 5 --
  it '5) every module file defines `def self.authors`' do
    missing = c::MODULE_FILES.reject do |f|
      c::NAMESPACE_INDEX_FILES.include?(c.rel(f)) || File.read(f).match?(/def self\.authors\b/)
    end
    msg = missing.map { |f| "  #{c.rel(f)}" }.join("\n")
    expect(missing).to be_empty, "modules missing `def self.authors`:\n#{msg}"
  end

  # ---------------------------------------------------------------- 6 --
  it '6) every public class method is documented in help with required/optional options (Google.help shape)' do
    misses = []
    c::MODULE_FILES.each do |path|
      next if c::NAMESPACE_INDEX_FILES.include?(c.rel(path))

      help = c.help_text(path)
      misses << "#{c.rel(path)}  missing method authors in help" unless help.match?(/\.authors(?!\w)/)
      pubs = c::ALL_METHODS.select do |m|
        m[:file] == path &&
          m[:decorator] == 'public_class_method' &&
          !c::HELP_SKIP.include?(m[:name])
      end
      pubs.each do |meth|
        name = meth[:name]
        unless help.match?(/\.#{Regexp.escape(name)}(?!\w)/)
          misses << "#{c.rel(path)}  missing method #{name} in help"
          next
        end
        misses << "#{c.rel(path)}  #{name}: missing purpose line above the method in help" unless c.purpose_above?(help, name)
        next unless meth[:arglist]&.strip == 'opts = {}'

        c.opts_keys(meth[:method_body]).each do |key|
          descs = help.scan(/#{Regexp.escape(key)}:\s*['"]((?:required|optional)\s*-\s*[^'"]+)/i).flatten
          if descs.empty?
            misses << "#{c.rel(path)}  #{name} option #{key}: missing required/optional description"
            next
          end
          next unless descs.any? { |d| c.thin_option_desc?(key, d) }

          misses << "#{c.rel(path)}  #{name} option #{key}: description too thin (say what to pass, not just the key name)"
        end
      end
    end
    extra = misses.length > 80 ? "\n... #{misses.length} total" : ''
    expect(misses).to be_empty, "#{misses.first(80).join("\n")}#{extra}"
  end
end
