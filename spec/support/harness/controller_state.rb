# frozen_string_literal: true

require 'pwn'
require 'json'

source, work, mode = ARGV
original_roots = PWN::Plugins::AISandbox.protected_roots
PWN::Plugins::AISandbox.define_singleton_method(:protected_roots) { [source, *original_roots] }
runtime = PWN::AI::Agent::RequestRuntime.new(request: 'Audit controller isolation', session_id: 'stateboundary', artifact_root: File.join(Dir.home, '.pwn', 'requests'), trace: false, retrieve: false)
Thread.current[:pwn_request_runtime] = runtime
# Independent finite writer inventory: include stores that do not exist yet,
# existing state, and writable-looking parent directories beneath HOME.
directories = %w[sessions artifacts logs learning metrics skills engagements missions runs curriculum finetune]
files = %w[learning.jsonl lessons.json policy.json policy_traj.jsonl metrics.json mistakes.json preferences.jsonl reward_sentinel.json open_goal.json skill_review.jsonl memory.json memory.archive.json memory.idx curriculum_kpi.jsonl pwn.yaml pwn.yaml.decryptor vault-secrets.json]
base = File.join(Dir.home, '.pwn')
directories.each { |name| FileUtils.mkdir_p(File.join(base, name)) }
if mode == 'aliased'
  path = File.join(base, 'sessions')
  target = File.join(File.dirname(work), 'session-state')
  FileUtils.mv(path, target)
  File.symlink(target, path)
end
files.each { |name| File.write(File.join(base, name), '{}') }
output = File.join(PWN::Plugins::AISandbox.workspace, 'allowed.txt')
PWN::AI::Agent::Registry.register(name: 'state_boundary_fixture', toolset: 'fixture', schema: { name: 'state_boundary_fixture', parameters: { type: 'object' } }, handler: lambda { |_args|
  attempts = {}
  directories.each do |name|
    path = File.join(base, name, 'redirect')
    attempts[name] = begin
      File.symlink(source, path)
      'writable'
    rescue Errno::EACCES, Errno::EPERM
      'denied'
    end
  end
  files.each do |name|
    attempts[name] = begin
      File.write(File.join(base, name), 'mutated')
      'writable'
    rescue Errno::EACCES, Errno::EPERM
      'denied'
    end
  end
  attempts['missing-policy-temp'] = begin
    File.symlink(source, File.join(base, '.policy-host-temp'))
    'writable'
  rescue Errno::EACCES, Errno::EPERM
    'denied'
  end
  File.write(output, 'output remains writable')
  attempts
})
result = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'state_boundary_fixture', arguments: '{}' } }))
puts JSON.generate(result: result, source_unchanged: Dir.empty?(source), output: File.read(output))
