# frozen_string_literal: true

require 'spec_helper'
require 'pry'
require 'stringio'

describe 'curses vault editing' do
  include_context 'pwn tmp sandbox'

  before do
    @prior_env = PWN::Env
    @prior_driver_opts = PWN::Env[:driver_opts]
    PWN::Env[:driver_opts] = {}
    @prior_redacted = PWN::EnvRedacted if PWN.const_defined?(:EnvRedacted)
    allow(Dir).to receive(:home).and_return(@tmp)
    @path = File.join(@tmp, '.pwn', 'pwn.yaml')
    FileUtils.mkdir_p(File.dirname(@path))
    @original = { ai: { active: 'anthropic', anthropic: { key: 'harmless-fixture', model: 'fixture-model' } }, extras: { list: ['one'], empty: nil } }
    File.write(@path, YAML.dump(@original))
    File.chmod(0o600, @path)
    PWN::Plugins::Vault.create(file: @path, decryptor_file: "#{@path}.decryptor")
    @decryptor = YAML.safe_load_file("#{@path}.decryptor", symbolize_names: true)
    allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@tmp, 'history')))
  end

  after do
    @prior_env[:driver_opts] = @prior_driver_opts
    PWN.send(:remove_const, :Env)
    PWN.const_set(:Env, @prior_env)
    PWN.send(:remove_const, :EnvRedacted) if PWN.const_defined?(:EnvRedacted)
    PWN.const_set(:EnvRedacted, @prior_redacted) if @prior_redacted
  end

  def read_fixture
    PWN::Plugins::Vault.dump({ file: @path }.merge(@decryptor))
  end

  it 'rejects deeply nested modal YAML without a stack failure, leaked diagnostic or ciphertext change' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.submit('/vault edit extras empty')
    before = File.binread(@path)
    console.instance_variable_get(:@vault_editor).replace("#{'[' * 10_000}harmless-private-fixture#{']' * 10_000}")
    expect { console.handle("\u0013") }.not_to raise_error
    expect(console.instance_variable_get(:@vault_error)).to include('Invalid YAML')
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('harmless-private-fixture', 'Invalid YAML')
    expect(File.binread(@path)).to eq(before)
  end

  it 'rejects deep encrypted input and decryptor YAML without modifying their bytes' do
    klass = PWN::Plugins::REPL::AIConsole::VaultEdit
    text = "#{'[' * 10_000}harmless-private-fixture#{']' * 10_000}"
    encrypted = klass.new([]).encrypt(text)
    File.binwrite(@path, encrypted)
    expect { klass.new([]) }.to raise_error(klass::Error, /Invalid YAML/)
    expect(File.binread(@path)).to eq(encrypted)
    File.chmod(0o600, "#{@path}.decryptor")
    File.write("#{@path}.decryptor", text)
    expect { klass.new([]) }.to raise_error(klass::Error, /Invalid YAML/)
    expect(File.binread(@path)).to eq(encrypted)
  end

  it 'rejects subtree edits whose merged document would exceed the YAML limit' do
    klass = PWN::Plugins::REPL::AIConsole::VaultEdit
    edit = klass.new(%w[extras empty])
    before = File.binread(@path)
    expect { edit.save("#{'[' * 100}0#{']' * 100}") }.to raise_error(klass::Error, /Invalid YAML/)
    expect(File.binread(@path)).to eq(before)
  end

  it 'uses the same configured vault and independent decryptor paths as pwn-vault' do
    custom = File.join(@tmp, 'custom-vault')
    sidecar = File.join(@tmp, 'custom-decryptor')
    FileUtils.cp(@path, custom)
    FileUtils.cp("#{@path}.decryptor", sidecar)
    File.chmod(0o600, custom)
    File.chmod(0o400, sidecar)
    canonical = File.binread(@path)
    key_bytes = File.binread(sidecar)
    PWN::Env[:driver_opts] = { pwn_env_path: custom, pwn_dec_path: sidecar }
    PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[ai anthropic model]).save('custom-model')
    expect(PWN::Plugins::Vault.dump({ file: custom }.merge(@decryptor)).dig(:ai, :anthropic, :model)).to eq('custom-model')
    expect(File.binread(@path)).to eq(canonical)
    expect(File.binread(sidecar)).to eq(key_bytes)
  end

  it 'routes an isolated modal without putting plaintext in session or history, and cancels unchanged' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    bytes = File.binread(@path)
    console.submit('/vault edit ai anthropic')
    expect(console.instance_variable_get(:@vault_editor).text).to include('harmless-fixture')
    console.handle('fixture-edit')
    console.handle("\e")
    expect(console.instance_variable_get(:@vault_editor)).to be_nil
    expect(File.binread(@path)).to eq(bytes)
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('harmless-fixture', 'fixture-edit')
    expect(Pry.history.to_a.join).not_to include('harmless-fixture', 'fixture-edit')
  end

  it 'rejects ambiguous YAML, unsafe tags and type changes without changing encrypted bytes' do
    edit = PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[ai anthropic])
    bytes = File.binread(@path)
    ['key: [unterminated', "---\nkey: one\n---\nkey: two", "key: one\nkey: two", '--- !ruby/object:Object {}', "key: 123\nmodel: fixture-model"].each do |text|
      expect { edit.save(text) }.to raise_error(PWN::Plugins::REPL::AIConsole::VaultEdit::Error)
      expect(File.binread(@path)).to eq(bytes)
    end
  end

  it 'merges unrelated concurrent changes but rejects changes to the selected scope' do
    edit = PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[ai anthropic])
    other = PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[extras list])
    other.save("- two\n")
    edit.save("key: replacement-fixture\nmodel: fixture-model\n")
    expect(read_fixture.dig(:extras, :list)).to eq(['two'])
    bytes = File.binread(@path)
    expect { edit.save("key: stale-fixture\nmodel: fixture-model\n") }.to raise_error(/scope changed/)
    expect(File.binread(@path)).to eq(bytes)
  end

  it 'supports scalars, arrays, null leaves and the full document but never indexes arrays or invents paths' do
    klass = PWN::Plugins::REPL::AIConsole::VaultEdit
    klass.new(%w[ai anthropic model]).save('new-model')
    klass.new(%w[extras empty]).save('null')
    expect(read_fixture.dig(:extras, :empty)).to be_nil
    klass.new(%w[extras empty]).save('new-value')
    expect(read_fixture.dig(:extras, :empty)).to eq('new-value')
    expect { klass.new(%w[extras list 0]) }.to raise_error(/Unknown key path/)
    expect { klass.new(['missing']) }.to raise_error(/Unknown key path/)
    expect { klass.new(['/tmp/not-a-vault']) }.to raise_error(/Unknown key path/)
    full = klass.new([])
    full.save(full.text)
    expect(read_fixture.dig(:ai, :anthropic, :model)).to eq('new-model')
    expect { klass.new([]).save('[]') }.to raise_error(/Type mismatch/)
  end

  it 'refuses missing or exposed decryptors and symlink vaults with redacted errors' do
    klass = PWN::Plugins::REPL::AIConsole::VaultEdit
    File.chmod(0o644, "#{@path}.decryptor")
    expect { klass.new([]) }.to raise_error(/private permissions/)
    File.unlink("#{@path}.decryptor")
    expect { klass.new([]) }.to raise_error(/Check encrypted/)
    File.rename(@path, "#{@path}.original")
    File.symlink("#{@path}.original", @path)
    expect { klass.new([]) }.to raise_error(/owned regular files/)
  end

  it 'saves on Ctrl+S before swarm shortcuts, blocks busy entry and never invokes refresh or a provider' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(PWN::Config).not_to receive(:refresh_env)
    expect(console).not_to receive(:start_request)
    allow(console).to receive(:busy?).and_return(true)
    expect(PWN::Plugins::REPL::AIConsole::VaultEdit).not_to receive(:new)
    console.submit('/vault edit')
    expect(console.instance_variable_get(:@vault_editor)).to be_nil
  end

  it 'saves on Ctrl+S with no secret text or errors in the session' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(PWN::Config).not_to receive(:refresh_env)
    expect(PWN::Plugins::Vault).not_to receive(:create)
    expect(console).not_to receive(:start_request)
    console.submit('/vault edit ai anthropic model')
    console.instance_variable_get(:@vault_editor).replace('fixture-saved-model')
    expect(console).not_to receive(:open_swarm)
    console.handle("\u0013")
    expect(console.instance_variable_get(:@vault_editor)).to be_nil
    expect(read_fixture.dig(:ai, :anthropic, :model)).to eq('fixture-saved-model')
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('fixture-saved-model')
    expect(PWN::Env.dig(:ai, :anthropic, :model)).to eq('fixture-saved-model')
  end

  it 'completes only schema key names without opening vaults, reading Env values or treating keys as files' do
    complete = lambda do |line|
      PWN::Plugins::REPL::AIConsoleCommands.complete(line: line, cursor: line.length)[:items].map { |item| item[:label] }
    end
    expect(PWN::Plugins::Vault).not_to receive(:dump)
    expect(complete.call('/vau')).to include('/vault')
    expect(complete.call('/vault ')).to eq(['edit'])
    expect(complete.call('/vault edit ')).to include('ai')
    expect(complete.call('/vault edit ai ')).to include('anthropic')
    expect(complete.call('/vault edit ai anthropic ')).to include('key', 'model')
    expect(complete.call('/vault edit ai anthropic key ')).to eq([])
    expect(complete.call('/vault edit /tmp/')).to eq([])
  end

  it 'cleans encrypted staging files on rename failure and preserves the original and Env' do
    edit = PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[ai anthropic model])
    before = File.binread(@path)
    env = PWN::Env
    allow(File).to receive(:rename).and_raise(Errno::EACCES, 'harmless-fixture')
    expect { edit.save('replacement') }.to raise_error(PWN::Plugins::REPL::AIConsole::VaultEdit::Error, /Check permissions/)
    expect(File.binread(@path)).to eq(before)
    expect(PWN::Env).to equal(env)
    expect(Dir.children(File.dirname(@path)).sort).to eq(%w[pwn.yaml pwn.yaml.decryptor])
  end

  it 'keeps invalid-YAML diagnostics inside the modal and supports Ctrl+C cancellation' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.submit('/vault edit')
    before = File.binread(@path)
    console.instance_variable_get(:@vault_editor).replace('harmless-invalid-secret: [')
    console.handle("\u0013")
    expect(console.instance_variable_get(:@vault_error)).to include('Invalid YAML')
    expect(console.instance_variable_get(:@vault_error)).not_to include('harmless-invalid-secret')
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('harmless-invalid-secret', 'Invalid YAML')
    console.handle("\u0003")
    expect(console.instance_variable_get(:@vault_editor)).to be_nil
    expect(File.binread(@path)).to eq(before)
  end

  it 'saves a subtree using the existing decryptor and preserves other configuration' do
    edit = PWN::Plugins::REPL::AIConsole::VaultEdit.new(%w[ai anthropic])
    expect(edit.text).to include('harmless-fixture')
    decryptor_bytes = File.binread("#{@path}.decryptor")
    edit.save("key: replacement-fixture\nmodel: fixture-model\n")
    expect(read_fixture).to eq(@original.merge(ai: @original[:ai].merge(anthropic: { key: 'replacement-fixture', model: 'fixture-model' })))
    expect(File.binread("#{@path}.decryptor")).to eq(decryptor_bytes)
    expect(File.binread(@path)).not_to include('replacement-fixture')
    expect(File.stat(@path).mode & 0o777).to eq(0o600)
    expect(PWN::EnvRedacted.dig(:ai, :anthropic, :key)).to include('REDACTED')
  end
end
