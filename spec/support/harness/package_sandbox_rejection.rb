# frozen_string_literal: true

# GEM_PATH also contains shared dependencies. Activate PWN from this install.
Gem::Specification.load(Dir.glob(File.join(Gem.dir, 'specifications/pwn-*.gemspec')).fetch(0)).activate
require 'pwn'

# RSpec has prepared the namespace. Only the public sandbox can start the
# block, and the marker is in an explicitly writable temporary workspace.
sandbox = PWN::AI::Sandbox
work = Dir.pwd
begin
  sandbox.protect_call(workspace: work, write_roots: [work]) do
    File.write(File.join(work, 'marker'), 'started')
  end
rescue PWN::AI::Sandbox::NotStarted => e
  File.write('fingerprint.json', JSON.generate(PWN::RuntimeFingerprint.report))
  puts JSON.generate(outcome: 'NOT_STARTED', error: e.message, activated_gem_root: Gem.loaded_specs.fetch('pwn').full_gem_path,
                     sandbox_source: File.realpath(sandbox.method(:protect_call).source_location.fetch(0)))
else
  abort 'expected the installed sandbox to reject the write before starting'
end
