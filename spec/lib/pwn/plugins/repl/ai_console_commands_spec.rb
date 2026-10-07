# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AIConsoleCommands do
  it 'advertises the renamed swarm surface in both completers' do
    line = '/swarm '
    labels = described_class.complete(line: line, cursor: line.length)[:items].map { |item| item[:label] }
    legacy = PWN::Plugins::REPL.pwn_ai_complete_command(line: line)
    [labels, legacy].each do |commands|
      expect(commands).to include('mission', 'agents', 'dm')
      expect(commands & %w[solve roster ask]).to be_empty
    end
  end

  it 'sorts every command group and nested live provider by displayed label' do
    values = %w[zulu alpha Alpha Bravo]
    allow(PWN::Plugins::REPL).to receive(:pwn_ai_engines).and_return(values)
    allow(PWN::Cron).to receive(:list).and_return(values.to_h { |value| [value, {}] })
    allow(PWN::Memory).to receive(:load).and_return(values.to_h { |value| [value, {}] })
    allow(PWN::Sessions).to receive(:list).and_return(values.map { |value| { id: value } })
    stub_const('PWN::Skills', values.to_h { |value| [value, {}] })
    allow(PWN::AI::MCP).to receive(:backends).and_return(values.map { |value| { name: value, tools: values } })
    controller = double(completion_context: { agents: values, jobs: values.map { |value| { id: value } } })
    allow(Dir).to receive(:exist?).with(PWN::AI::Agent::Swarm::SWARM_ROOT).and_return(true)
    allow(Dir).to receive(:children).with(PWN::AI::Agent::Swarm::SWARM_ROOT).and_return(values)
    lines = ['/'] + described_class::COMMANDS.map { |command| "#{command} " } +
            ['/cron run ', '/memory recall ', '/sessions resume ', '/skills recall ', '/model list ', '/learning list ',
             '/mcp use ', '/mcp call ', '/swarm dm ', '/swarm cancel ', '/swarm use ', '/swarm debate ']
    lines.each do |line|
      items = described_class.complete(line: line, cursor: line.length, swarm: controller)[:items]
      labels = items.map { |item| item[:label] }
      expect(labels).to eq(labels.sort_by { |label| [label.downcase, label] }), line
      items.each { |item| expect(item[:text]).to eq(line == '/' ? item[:label] : "#{line}#{item[:label]}") }
    end
    line = '/swarm dm '
    expect(described_class.complete(line: line, cursor: line.length, swarm: controller)[:items].first[:label]).to eq('Alpha')
    values << 'aardvark'
    expect(described_class.complete(line: line, cursor: line.length, swarm: controller)[:items].first[:label]).to eq('aardvark')
  end

  it 'completes command names and parameter positions without a provider call' do
    allow(PWN::Plugins::REPL).to receive(:pwn_ai_engines).and_return(%w[openai grok])
    first = described_class.complete(line: '/mo', cursor: 3)
    expect(first[:items].map { |item| item[:label] }).to include('/model')
    expect(described_class.complete(line: '/', cursor: 1)[:items].map { |item| item[:label] }).to include('/system-role')
    expect(described_class.complete(line: '/sys', cursor: 4)[:items].map { |item| item[:label] }).to eq(['/system-role'])
    engines = described_class.complete(line: '/model ', cursor: 7)
    expect(engines[:items].map { |item| item[:label] }).to include('openai', 'list')
    expect(engines[:items].map { |item| item[:text] }).to include('/model openai')
    verbose = described_class.complete(line: '/verbose ', cursor: 9)
    expect(verbose[:items].map { |item| item[:label] }).to eq(%w[off on])
    free = described_class.complete(line: '/steer keep ', cursor: 12)
    expect(free[:items]).to be_empty
    expect(free[:hint]).to include('free text')
  end

  it 'completes PWN constants and filesystem paths as they are typed' do
    hits = described_class.complete(line: 'inspect PWN::Plug', cursor: 16)
    expect(hits[:items].map { |item| item[:label] }).to include('PWN::Plugins::')
    expect(hits[:hint]).to eq('PWN constant')
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'sample.txt'), 'x')
      path = described_class.complete(line: "#{dir}/sam", cursor: "#{dir}/sam".length)
      expect(path[:items].map { |item| item[:label] }).to include(File.join(dir, 'sample.txt'))
      expect(path[:hint]).to eq('path')
    end
  end

  it 'does not autoload every constant candidate or fail on a scalar namespace' do
    mod = Module.new
    mod.autoload(:Unloaded, '/not/a/real/dependency.rb')
    mod.const_set(:Scalar, 42)
    stub_const('PWN::CompletionProbe', mod)
    result = described_class.complete(line: 'PWN::CompletionProbe::', cursor: 22)
    expect(result[:items].map { |item| item[:label] }).to include('PWN::CompletionProbe::Unloaded::')
    expect(mod.autoload?(:Unloaded)).not_to be_nil
    line = 'PWN::CompletionProbe::Scalar::'
    expect(described_class.complete(line: line, cursor: line.length)[:items]).to be_empty
  end

  it 'recognizes absolute paths outside a hardcoded root list without swallowing slash commands' do
    expect(PWN::Plugins::REPL).to receive(:pwn_ai_complete_path).with(target: '/srv/probe', line: '/srv/probe').and_return(['/srv/probe.txt'])
    expect(described_class.complete(line: '/srv/probe', cursor: 10)[:items].first[:label]).to eq('/srv/probe.txt')
    expect(described_class.complete(line: '/mo', cursor: 3)[:items].first[:label]).to eq('/model')
  end

  it 'preserves a Unicode suffix when replacing the token at the cursor' do
    result = described_class.complete(line: '/verbose o café', cursor: 10)
    chosen = result[:items].find { |item| item[:label] == 'on' }
    expect(chosen[:text]).to eq('/verbose on café')
    expect(chosen[:text].scan(/\X/)[chosen[:cursor]]).to eq(' ')
  end

  it 'keeps every command reachable and completes only the prefix before a mid-token cursor' do
    labels = described_class.complete(line: '/', cursor: 1)[:items].map { |item| item[:label] }
    expect(labels).to include('/swarm', '/verbose', '/steer', '/status')
    result = described_class.complete(line: '/verbose ox café', cursor: 10)
    expect(result[:items].map { |item| item[:text] }).to include('/verbose on café')
  end
end
