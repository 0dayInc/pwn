# frozen_string_literal: true

require 'spec_helper'

# Guards against cosmetic version-staleness in docs.
#
# Every rendered REPL prompt in README + documentation/ must use the
# evergreen placeholder `pwn[CURRENT_VERSION]:NNN >>>` — never a
# hard-coded `pwn[vX.Y.Z]:NNN >>>`. The real prompt shows PWN::VERSION
# at runtime; docs that pin a literal version rot on every release and
# get flagged by users as "wrong version" noise.
#
# If this spec fails you copy-pasted a live prompt into a doc. Replace
# the `vX.Y.Z` with `CURRENT_VERSION` and it will pass.
RSpec.describe 'documentation REPL prompt version placeholder' do
  repo_root = File.expand_path('../..', __dir__)
  doc_globs = [
    File.join(repo_root, 'README.md'),
    File.join(repo_root, 'documentation', '**', '*.md')
  ]
  hardcoded = /pwn\[v\d+\.\d+\.\d+\]:\d+ >>>/

  Dir.glob(doc_globs).each do |path|
    rel = path.delete_prefix("#{repo_root}/")

    it "#{rel} uses pwn[CURRENT_VERSION]:NNN >>> (no hard-coded vX.Y.Z)" do
      offending = File.foreach(path)
                      .each_with_index
                      .select { |line, _| line.match?(hardcoded) }
                      .map { |line, i| "  #{rel}:#{i + 1}: #{line.strip}" }
      expect(offending).to be_empty, <<~MSG
        Hard-coded REPL prompt version(s) found — replace vX.Y.Z with CURRENT_VERSION:
        #{offending.join("\n")}
      MSG
    end
  end
end
