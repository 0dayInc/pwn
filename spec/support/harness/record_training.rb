# frozen_string_literal: true

# Host-only independent receipt, AFTER the actual training CLI has exited.
require 'json'
require 'digest'
raise 'temporary HOME required' unless Dir.home.start_with?('/tmp/')

require 'pwn'
receipt = JSON.parse(File.read(ARGV.fetch(0), encoding: Encoding::UTF_8))
receipt.fetch('checks').each do |check|
  path = check.fetch('path')
  raise 'training artifact changed' unless File.file?(path) && !File.symlink?(path) && Digest::SHA256.file(path).hexdigest == check.fetch('observed_sha256') && check.fetch('passed')
end
options = { task: receipt.fetch('prompt'), success: true,
            details: 'Host independently checked synthetic training artifact bytes; not model-quality evidence.',
            tags: %w[synthetic_fixture independently_checked] }
row = PWN::AI::Agent::Learning.note_outcome(options)
puts JSON.generate(row)
