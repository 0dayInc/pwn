# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

describe 'pwn-vault Config RuntimeError retry' do
  # Source/behavior contract: after Vault.edit, Config.refresh_env must run
  # inside the command so RuntimeError from invalid pwn.yaml prints the error,
  # waits on "Press Enter to Resolve" via $stdin.gets, then re-opens the editor.
  # Validation must NOT be deferred solely to the PS1 hook.
  let(:repl_src) { File.read(PWN::Plugins::REPL.method(:add_commands).source_location.first) }
  let(:vault_src) { File.read(PWN::Plugins::Vault.method(:edit).source_location.first) }
  let(:block) do
    start = repl_src.index("Pry::Commands.create_command 'pwn-vault'")
    stop = repl_src.index("Pry::Commands.create_command 'toggle-pwn-ai-debug'")
    repl_src[start...stop]
  end

  it 'validates via PWN::Config.refresh_env inside the pwn-vault command' do
    expect(block).to include('PWN::Config.refresh_env')
    expect(block).to include('PWN::Plugins::Vault.edit')
    expect(block).to match(/loop do/)
    expect(block).to match(/rescue RuntimeError/)
  end

  it 'prints the error, prompts, "Press ENTER to resolve...", and waits on $stdin.gets' do
    expect(block).to include('puts e.message')
    expect(block).to include("print 'Press ENTER to resolve...'")
    expect(block).to include('$stdin.gets')
  end

  it 'clears refresh_pwn_env on Config RuntimeError so PS1 does not re-raise' do
    expect(block).to include('Pry.config.refresh_pwn_env = false')
  end

  it 'defaults decryptor path to <pwn.yaml>.decryptor (Config canonical)' do
    # Ruby source uses "#{pwn_env_path}.decryptor" — match that expression.
    expect(block).to include('pwn_env_path}.decryptor')
    expect(block).not_to include('pwn.decryptor.yaml')
  end

  it 'Vault.edit alone still only flags refresh (validation stays in command)' do
    expect(vault_src).to include('Pry.config.refresh_pwn_env = true')
    # edit method should not call refresh_env itself
    edit_start = vault_src.index('def self.edit')
    edit_chunk = vault_src[edit_start...(edit_start + 1200)]
    expect(edit_chunk).not_to include('refresh_env')
  end

  describe 'retry loop behavioral double' do
    it 'prints error + resolve prompt, waits on $stdin.gets, re-invokes edit until refresh_env succeeds' do
      edit_calls = 0
      refresh_calls = 0
      gets_calls = 0
      stdout = StringIO.new

      vault = Module.new do
        define_singleton_method(:edit) do |**_opts|
          edit_calls += 1
          true
        end
      end

      config = Module.new do
        define_singleton_method(:refresh_env) do |**_opts|
          refresh_calls += 1
          raise 'ERROR: Unsupported AI Engine: bogon' if refresh_calls < 3

          true
        end
      end

      # Mirror the production control flow without vim/Pry command plumbing.
      # Use $stdin.gets (not Kernel#gets) so ARGF/ARGV from rspec/rake cannot
      # steal the read the way bare gets does under `rake`.
      original_stdout = $stdout
      original_stdin = $stdin
      begin
        $stdout = stdout
        $stdin = StringIO.new("\n\n")
        loop do
          vault.edit(file: 'x', key: 'k', iv: 'i')
          begin
            config.refresh_env(pwn_env_path: 'x', pwn_dec_path: 'y', key: 'k', iv: 'i')
            break
          rescue RuntimeError => e
            puts e
            puts 'Press Enter to Resolve'
            $stdin.gets
            gets_calls += 1
          end
        end
      ensure
        $stdout = original_stdout
        $stdin = original_stdin
      end

      expect(edit_calls).to eq(3)
      expect(refresh_calls).to eq(3)
      expect(gets_calls).to eq(2)
      out = stdout.string
      expect(out).to include('ERROR: Unsupported AI Engine: bogon')
      expect(out.scan('Press Enter to Resolve').size).to eq(2)
    end

    it 'does not retry when refresh_env succeeds on first try' do
      edit_calls = 0
      refresh_calls = 0
      vault = Module.new do
        define_singleton_method(:edit) do |**_|
          edit_calls += 1
        end
      end
      config = Module.new do
        define_singleton_method(:refresh_env) do |**_|
          refresh_calls += 1
        end
      end

      loop do
        vault.edit
        begin
          config.refresh_env
          break
        rescue RuntimeError
          raise 'unexpected retry'
        end
      end

      expect(edit_calls).to eq(1)
      expect(refresh_calls).to eq(1)
    end
  end
end
