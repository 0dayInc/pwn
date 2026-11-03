# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'README security overview', :aggregate_failures do
  let(:root) { File.expand_path('../..', __dir__) }
  let(:readme) { File.read(File.join(root, 'README.md')) }
  let(:security) do
    readme[/^##### \*\*Vault and Sandboxing\*\* #####\n(.*?)(?=^#### )/m, 1].to_s.gsub(/\s+/, ' ')
  end

  it 'links a security subsection under Why PWN without replacing How PWN Works' do
    expect(readme).to include('[Vault and Sandboxing](#vault-and-sandboxing)')
    expect(readme).to match(/^#### \*\*Why PWN\*\* ####.*^##### \*\*Vault and Sandboxing\*\* #####.*^#### \*\*How PWN Works\*\* ####/m)
  end

  it 'explains credential handling at the tool boundary and engagement loot scope' do
    expect(security).to include('security research', 'bug bounty hunting', 'penetration testing',
                                'at rest', '{{vault:label}}', 'Dispatch', 'tool boundary',
                                'prompts', 'logs', 'engagement', 'provenance', 'across engagements')
  end

  it 'documents the mandatory local boundary independently of optional sandbox profiles' do
    expect(security).to include('untrusted PoCs', 'prompt injection', '~/.pwn/workspaces/runtime',
                                'original operator request', 'parent', 'source', 'controller state',
                                'read-only even if named', 'fail closed', 'Landlock', 'seccomp',
                                'namespace', '`strict`', '`permissive`', '`off`')
  end

  it 'keeps encryption, provider privacy and operator responsibilities distinct' do
    expect(security).to include('active process', 'LLM-provider privacy', 'whole-filesystem',
                                'evidence/artifact encryption', 'redaction can miss',
                                'not authorization', 'network isolation', 'perfect container',
                                'guarantee against bugs', 'target authorization', 'least-privilege',
                                'retention')
  end

  it 'links implementation and boundary documentation with existing local targets' do
    expect(security).to include('(lib/pwn/plugins/vault.rb)', '(lib/pwn/ai/agent/dispatch.rb)',
                                '(documentation/Runtime-Source-Protection.md)',
                                '(documentation/Mission-Cancellation.md)',
                                '(documentation/Configuration.md)', '(documentation/YubiKey-Vaults.md)')
    refs = readme.scan(/\]\((?!https?:|#|mailto:)([^)\s]+)\)/).flatten.uniq
    broken = refs.reject { |ref| File.exist?(File.expand_path(ref.split('#', 2).first, root)) }
    expect(broken).to be_empty, "broken README relative links: #{broken.join(', ')}"
  end
end
