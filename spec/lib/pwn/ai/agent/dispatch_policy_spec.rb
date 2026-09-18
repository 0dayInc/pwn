# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

RSpec.describe PWN::AI::Agent::Dispatch do
  around do |example|
    Dir.mktmpdir('dispatch-policy') do |dir|
      @dir = dir
      example.run
    end
  end

  after do
    %w[policy_echo budget_probe budget_cap].each { |name| PWN::AI::Agent::Registry.instance_variable_get(:@entries).delete(name) }
    Thread.current[:pwn_dispatch_budget] = nil
  end

  def dispatch(name, args, **options)
    JSON.parse(described_class.call({ tool_call: { function: { name: name, arguments: JSON.generate(args) } }, scope_path: File.join(@dir, 'absent.yaml') }.merge(options)), symbolize_names: true)
  end

  it 'transports literal unquoted ellipses without heuristic rejection or byte rewriting' do
    PWN::AI::Agent::Registry.discover
    out = dispatch('shell', { command: 'printf %s ...', timeout: 2 })
    expect(out.dig(:result, :stdout)).to eq('...')
    out = dispatch('pwn_eval', { code: 'puts %q[ ... ]', timeout: 2 })
    expect(out.dig(:result, :stdout)).to include(' ... ')
  end

  it 'explains an elided command after markdown data and accepts one corrected call' do
    PWN::AI::Agent::Registry.discover
    command = "cat <<-'MD'\n# Résumé ... inline prose\n...\n\tMD\n...\n"
    denied = dispatch('shell', { command: command, timeout: 2 }).fetch(:result)
    expect(denied).to include(error: 'invalid_payload', code: 'SYNTAX_DENY', rule_id: 'payload.placeholder', match: '...')
    expect(denied[:offset]).to eq(command.b.rindex("\n...".b) + 1)
    expect(command.byteslice(denied[:offset], denied[:match].bytesize)).to eq('...')
    expect(denied[:remedy]).to include('placeholder_ok', 'base64', 'data')
    expect(denied[:remedy]).to include('does not bypass')
    corrected_command = command.byteslice(0, denied[:offset])
    corrected = dispatch('shell', { command: corrected_command, timeout: 2 })
    expect(corrected.dig(:result, :exit)).to eq(0)
    expect(corrected.dig(:result, :stdout)).to include("# Résumé ... inline prose\n...\n")
  end

  it 'preserves decoded byte offsets through base64 and does not present encoding as a validation bypass' do
    PWN::AI::Agent::Registry.discover
    command = "cat <<-'MD'\n# Résumé ...\n…\n\tMD\n…\n"
    args = { encoding: 'base64', data: Base64.strict_encode64(command), timeout: 2 }
    denied = dispatch('shell', args).fetch(:result)
    expect(denied[:match]).to eq('…')
    expect(denied[:offset]).to eq(command.b.rindex('…'.b))
    expect(denied[:byte_range]).to eq([denied[:offset], denied[:offset] + '…'.bytesize])
    corrected = dispatch('shell', args.merge(data: Base64.strict_encode64(command.byteslice(0, denied[:offset]))))
    expect(corrected.dig(:result, :exit)).to eq(0)
    expect(corrected.dig(:result, :stdout)).to include('…')
  end

  it 'explains schema invalid_payload errors with the field and correction' do
    PWN::AI::Agent::Registry.discover
    denied = dispatch('shell', { command: 'printf ok', timeout: 20_000 })
    expect(denied).to include(error: 'invalid_payload', rule_id: 'schema.maximum', offset: nil)
    expect(denied[:match]).to eq('20000')
    expect(denied[:remedy]).to include('/timeout', '10800')
  end

  it 'writes Ruby literal ellipses as data and denies a code stub before side effects' do
    PWN::AI::Agent::Registry.discover
    path = File.join(@dir, 'document.md')
    code = "doc_with_ellipsis = <<~DOC\n  # Résumé\n  ...\n  def foo(<3dots>)\nDOC\nFile.write(#{path.inspect}, doc_with_ellipsis)"
    result = dispatch('pwn_eval', { code: code, timeout: 2 })
    expect(result.dig(:result, :error)).to be_nil
    expect(File.read(path)).to eq("# Résumé\n...\ndef foo(<3dots>)\n")
    File.delete(path)
    stub = "File.write(#{path.inspect}, 'should not execute'); def foo(<3dots>); end"
    denied = dispatch('pwn_eval', { code: stub, timeout: 2 }).fetch(:result)
    expect(denied).to include(error: 'invalid_payload', rule_id: 'payload.placeholder', match: '<3dots>')
    expect(denied[:offset]).to eq(stub.b.index('<3dots>'))
    expect(File.exist?(path)).to eq(false)
  end

  it 'loads a YAML-whitelisted plugin method as a callable tool' do
    PWN::AI::Agent::Registry.discover
    entry = PWN::AI::Agent::Registry.lookup(name: 'host_os_type')
    expect(entry).not_to be_nil
    expect(dispatch('host_os_type', {})[:success]).to be(true)
  end

  it 'hard-denies out-of-scope declared targets and audits without executing' do
    PWN::AI::Agent::Registry.discover
    audit = File.join(@dir, 'audit.jsonl')
    policy = { allowed_cidrs: ['192.0.2.0/24'], allowed_domains: ['*.example.test'], allowed_ports: [443], risk_gates: { high: 'auto' } }
    out = dispatch('shell', { command: 'printf should-not-run', target: '198.51.100.1', port: 443 }, scope_policy: policy, audit_path: audit)
    expect(out[:denied]).to eq('out_of_scope')
    expect(JSON.parse(File.read(audit))['reason']).to eq('out_of_scope')
    expect(out[:result]).to be_nil
  end

  it 'requires a trusted prompt callback and never permits an approval to override scope' do
    PWN::AI::Agent::Registry.discover
    options = { scope_policy: { allowed_cidrs: ['192.0.2.0/24'], allowed_ports: [443], risk_gates: { high: 'prompt' } }, audit_path: File.join(@dir, 'prompt.jsonl') }
    args = { command: 'printf approved', target: '192.0.2.1', port: 443, approved: true }
    expect(dispatch('shell', args, **options)[:denied]).to eq('approval_required')
    expect(dispatch('shell', args, **options, approval_callback: ->(_request) { true }).dig(:result, :stdout)).to eq('approved')
    expect(dispatch('shell', args.merge(target: '198.51.100.1'), **options, approval_callback: ->(_request) { raise 'must not prompt' })[:denied]).to eq('out_of_scope')
  end

  it 'escalates identical timed-out payloads automatically in a caller-owned ledger' do
    calls = []
    PWN::AI::Agent::Registry.register(name: 'budget_probe', schema: { parameters: { type: 'object', properties: { command: { type: 'string' }, timeout: { type: 'integer' } } } }, handler: lambda { |args|
      calls << args.dup
      { error: 'timeout after test deadline' }
    })
    ledger = {}
    dispatch('budget_probe', { command: 'same', timeout: 2 }, budget_ledger: ledger)
    out = dispatch('budget_probe', { timeout: 1, command: 'same' }, budget_ledger: ledger)
    expect(calls.map { |args| args[:timeout] }).to eq([2, 182])
    expect(out.dig(:budget, :spent_s)).to eq(184)
    expect(out.dig(:result, :next_timeout)).to eq(362)
    blocked = dispatch('budget_probe', { command: 'changed', timeout: 2 }, budget_ledger: ledger)
    expect(blocked[:error]).to eq('retry_required')
    expect(calls.length).to eq(2)
  end

  it 'caps cumulative payload time at 10800 seconds and permits only ten actual mutations' do
    calls = []
    PWN::AI::Agent::Registry.register(name: 'budget_cap', schema: { parameters: { type: 'object', properties: { command: { type: 'string' }, timeout: { type: 'integer' } } } }, handler: lambda { |args|
      calls << args.dup
      { error: 'timeout' }
    })
    ledger = {}
    dispatch('budget_cap', { command: 'original', timeout: 10_700 }, budget_ledger: ledger)
    out = dispatch('budget_cap', { command: 'original', timeout: 1 }, budget_ledger: ledger)
    expect(calls.last[:timeout]).to eq(100)
    expect(out[:error]).to eq('budget_exhausted')
    expect(out.dig(:budget, :spent_s)).to eq(10_800)
    expect(dispatch('budget_cap', { command: 'original' }, budget_ledger: ledger)[:error]).to eq('budget_exhausted')
    10.times { |n| dispatch('budget_cap', { command: "mutation-#{n}", timeout: 10_800 }, budget_ledger: ledger) }
    expect(ledger[:mutations]).to eq(10)
    expect(dispatch('budget_cap', { command: 'eleventh', timeout: 1 }, budget_ledger: ledger)[:error]).to eq('budget_exhausted')
    expect(calls.length).to eq(12)
    expect(dispatch('host_os_type', {}, budget_ledger: ledger)[:success]).to be(true)
    expect(dispatch('budget_cap', { command: 'fresh', timeout: 1 }, budget_ledger: {})[:error]).not_to eq('budget_exhausted')
  end

  it 'preserves shell backslash-newline bytes inside quoted data' do
    PWN::AI::Agent::Registry.discover
    command = "printf %s 'before\\\nafter'"
    expect(dispatch('shell', { command: command, timeout: 2 }).dig(:result, :stdout)).to eq("before\\\nafter")
  end

  it 'accounts for a real shell timeout and retries the identical command successfully' do
    PWN::AI::Agent::Registry.discover
    ledger = {}
    args = { command: 'sleep 2; printf retry-ok', timeout: 1 }
    first = dispatch('shell', args, budget_ledger: ledger)
    expect(first.dig(:result, :error)).to match(/timeout/)
    expect(first.dig(:budget, :spent_s)).to eq(1)
    second = dispatch('shell', args, budget_ledger: ledger)
    expect(second.dig(:budget, :timeout_s)).to eq(181)
    expect(second.dig(:result, :stdout)).to eq('retry-ok')
  end

  it 'applies manifest parameter constraints to existing tools' do
    PWN::AI::Agent::Registry.discover
    expect(dispatch('shell', { command: '', timeout: 2 })[:error]).to eq('invalid_payload')
    expect(dispatch('pwn_eval', { code: 'puts 1', timeout: 20_000 })[:error]).to eq('invalid_payload')
  end

  it 'never dispatches a zero-second deadline when less than a second remains' do
    PWN::AI::Agent::Registry.discover
    ledger = {}
    args = { command: 'printf tiny', timeout: 1 }
    first = dispatch('shell', args, budget_ledger: ledger)
    ledger[:chains]['shell'][:payloads][first.dig(:budget, :payload_hash)][:spent_s] = 10_799.75
    expect(dispatch('shell', args, budget_ledger: ledger)[:error]).to eq('budget_exhausted')
  end

  it 'does not reject valid POSIX variables as incidental bash-looking content' do
    PWN::AI::Agent::Registry.discover
    out = dispatch('shell', { command: 'RANDOM=opaque; printf %s $RANDOM', timeout: 2 })
    expect(out.dig(:result, :stdout)).to eq('opaque')
  end

  it 'rejects schema type violations before a handler sees them' do
    invoked = false
    PWN::AI::Agent::Registry.register(name: 'policy_echo', schema: { parameters: { type: 'object', required: ['value'], properties: { value: { type: 'string' } } } }, handler: ->(_args) { invoked = true })
    out = dispatch('policy_echo', { value: 42 })
    expect(out[:error]).to eq('invalid_payload')
    expect(invoked).to be(false)
  end
end
