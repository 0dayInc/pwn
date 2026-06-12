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

  module_function

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
        arglist: m[4], # nil = zero-arg endless or paren-less; '' = ()
        body_excerpt: lines[(idx + 1)..(idx + 60)]&.join.to_s
      }
    end
    out
  end

  ALL_METHODS = MODULE_FILES.flat_map { |f| scan_methods(f) }.freeze

  def rel(path)
    path.sub("#{ROOT}/", '')
  end
end

describe 'PWN module conventions' do
  c = PWNConventions

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
end
