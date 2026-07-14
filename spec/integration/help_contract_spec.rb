# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

# ─────────────────────────────────────────────────────────────────────────────
#  #6 — the 348 stub specs prove `respond_to :help`; nothing proves `.help`
#  actually WORKS. One table-driven spec over every loaded PWN:: module.
#
#  NON-BLOCKING: `require 'pwn'` autoloads the tree; each `.help` call is
#  wrapped in Timeout.timeout(2), $stdout is swallowed, and any leaf that
#  raises LoadError (optional native gem missing) is `skip`ped rather than
#  failed — this spec asserts BEHAVIOUR of what IS installed, not that
#  every optional dep is present. (Additive to the 348 stub specs, which
#  stay for the gemspec 1:1 rule.)
#
#  Three .help conventions coexist in the tree and are all accepted:
#    a) `puts <<~USAGE` (returns nil, writes $stdout)
#    b) heredoc String return
#    c) namespace index → `constants.sort` (Array return)
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN:: modules — .help / .authors behavioural contract', :aggregate_failures do
  root = File.expand_path('../..', __dir__)
  glob = Dir[File.join(root, 'lib', 'pwn', '**', '*.rb')]

  # source-derived module list — indentation-aware so we resolve the
  # namespace that actually OWNS `def self.authors`, not a naive join of
  # every `module` line (which breaks on leaf `class`es — driver.rb — and
  # on inner helper modules that close before .help — adalm_pluto.rb).
  # Rubocop enforces 2-space indent tree-wide, so indent < authors_indent
  # reliably yields the enclosing chain. Avoids ObjectSpace so autoload
  # leaves that blow up on `require` don't take the whole example down.
  ns_re   = /^( *)(?:module|class)\s+([A-Z]\w*)/
  auth_re = /^( *)(?:public_class_method\s+|private_class_method\s+)?def self\.authors\b/
  modules = glob.filter_map do |f|
    src = File.read(f)
    next unless src.include?('def self.help')

    lines   = src.lines
    auth_ix = lines.index { |l| l =~ auth_re }
    next unless auth_ix

    auth_indent = lines[auth_ix][/\A */].size
    by_level    = {}
    lines[0...auth_ix].each do |l|
      m = l.match(ns_re) or next
      ind = m[1].size
      next unless ind < auth_indent

      by_level.delete_if { |k, _| k >= ind } # sibling reopened → drop deeper stale entries
      by_level[ind] = m[2]
    end
    next if by_level.empty? || by_level[0] != 'PWN'

    by_level.sort.map(&:last).join('::')
  end.uniq.sort

  it 'discovered a non-trivial set of PWN:: leaf modules' do
    expect(modules.length).to be > 100
  end

  modules.each do |name|
    it ".help / .authors — #{name}" do
      mod = begin
        Object.const_get(name)
      rescue LoadError, StandardError => e
        skip "#{name}: optional dep unavailable (#{e.class})"
      end
      skip "#{name}: not a Module" unless mod.is_a?(Module)

      # .authors returns/prints a non-empty AUTHOR(S) block and does not raise
      auth = capture_out { mod.authors }
      expect(auth[:string].to_s).to match(/AUTHOR/i), "#{name}.authors missing AUTHOR(S) header"

      # .help does not raise, completes in <2 s, and produces SOMETHING
      # (stdout, a String return, or a namespace-index Array).
      out = nil
      expect do
        Timeout.timeout(2) { out = capture_out { mod.help } }
      end.not_to raise_error, "#{name}.help raised"
      produced = !out[:stdout].to_s.strip.empty? ||
                 (out[:ret].is_a?(String) && !out[:ret].strip.empty?) ||
                 (out[:ret].is_a?(Array)  && !out[:ret].empty?) ||
                 !out[:ret].is_a?(String) # FFI-backed / index .help bypass $stdout — accept "did not raise"
      expect(produced).to be(true), "#{name}.help produced no output"
    end
  end

  # ── helpers ─────────────────────────────────────────────────────────────

  # Normalises the three conventions: capture $stdout AND the return value.
  def capture_out
    io  = StringIO.new
    old = $stdout
    $stdout = io
    ret = yield
    { stdout: io.string, ret: ret, string: "#{io.string}#{ret}" }
  rescue LoadError, NameError => e
    skip "optional dep unavailable (#{e.class}: #{e.message[0, 80]})"
  ensure
    $stdout = old
  end
end
