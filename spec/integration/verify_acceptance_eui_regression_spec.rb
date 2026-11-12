# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'EUI-LOGIC-001 acceptance through CLI, DAG, Dispatch, Registry and Mission' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::TaskDAG::ROOT', File.join(@tmp, 'runs'))
    stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(@tmp, 'artifacts'))
    allow(PWN::Config).to receive(:refresh_env).and_return(PWN::Env)
    @saved_runtime = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = nil
    @agent_cfg[:artifact_max_tokens] = 1024
    PWN::AI::Agent::Registry.discover
  end

  after do
    Thread.current[:pwn_request_runtime] = @saved_runtime
  end

  def approved_plan(path, paged)
    checks = [{ type: 'file_grep', path: path, pattern: '\\Aaccepted\\z' }] * (paged ? 64 : 1)
    steps = [
      { id: 'acceptance', tool: 'verify', args: { checks: checks } },
      { id: 'dependent', tool: 'verify', args: { checks: [{ type: 'file_exists', path: __FILE__ }] }, dependencies: ['acceptance'] }
    ]
    dag = PWN::AI::Agent::TaskDAG.plan(request: 'Require this report before completion', steps: steps)
    approval = File.join(@tmp, 'approved.yaml')
    File.write(approval, YAML.dump(JSON.parse(JSON.generate(dag))))
    PWN::AI::Agent::Mission.begin!(id: 'acceptance', request: dag[:request])
    approval
  end

  def cli_report(*arguments)
    output = StringIO.new
    status = PWN::AI::CLI.run(argv: [*arguments, '--mission', 'acceptance'], output: output)
    [status, JSON.parse(output.string, symbolize_names: true)]
  end

  def checkpoints(report)
    File.readlines(File.join(report[:dir], 'checkpoints.jsonl')).map { |line| JSON.parse(line, symbolize_names: true) }
  end

  def acceptance_result(report, paged)
    result = report[:results].first[:result]
    if paged
      artifact = result.fetch(:artifact)
      bytes = File.binread(artifact[:path])
      expect(Digest::SHA256.hexdigest(bytes)).to eq(artifact[:sha256])
      expect(bytes.bytesize).to eq(artifact[:bytes])
      full = JSON.parse(bytes, symbolize_names: true)
      expect(result[:success]).to eq(full[:passed])
      full
    else
      expect(result).not_to have_key(:artifact)
      result
    end
  end

  [false, true].each do |paged|
    %w[missing mismatched].each do |condition|
      it "blocks a #{condition} required check, retries and resumes after repair (paged=#{paged})" do
        path = File.join(@tmp, 'required-report.txt')
        File.write(path, 'not accepted') if condition == 'mismatched'
        approval = approved_plan(path, paged)
        status, report = cli_report('--execute', approval)
        aggregate_failures do
          expect(status).to eq(1)
          expect(report[:ok]).to be(false)
          expect(report[:results].map { |row| row[:id] }).to eq(['acceptance'])
          expect(acceptance_result(report, paged)[:passed]).to be(false)
          expect(checkpoints(report).map { |row| row[:status] }).to eq(['failed'])
          expect(PWN::AI::Agent::Mission.complete!(id: 'acceptance')).to include(ok: false, reason: 'checkpoints')
          expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(false)
        end

        retry_status, retry_report = cli_report('--resume', report[:run_id])
        expect(retry_status).to eq(1)
        expect(retry_report[:results].map { |row| row[:id] }).to eq(['acceptance'])
        resumed = PWN::AI::Agent::Mission.resume_run(id: 'acceptance')
        expect(resumed).to include(ok: false, resumed: true)
        expect(resumed[:text]).to include('Failed steps: acceptance')
        expect(resumed[:text]).not_to include('Completed steps: acceptance')
        expect(PWN::AI::Agent::Mission.current(id: 'acceptance')[:last_completed_step]).to be_nil
        expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(false)
        expect(checkpoints(report).map { |row| row[:status] }).to eq(%w[failed failed failed])

        File.write(path, 'accepted')
        fixed_status, fixed = cli_report('--resume', report[:run_id])
        expect(fixed_status).to eq(0)
        expect(fixed[:ok]).to be(true)
        expect(fixed[:results].map { |row| row[:id] }).to eq(%w[acceptance dependent])
        expect(acceptance_result(fixed, paged)[:passed]).to be(true)
        expect(checkpoints(report).map { |row| row[:status] }).to eq(%w[failed failed failed completed completed])
        completed = PWN::AI::Agent::Mission.resume_run(id: 'acceptance')
        expect(completed).to include(ok: true, results: [])
        expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(true)
        expect(checkpoints(report).map { |row| row[:status] }).to eq(%w[failed failed failed completed completed])
      end
    end

    it "completes a passing required check through the same entry point (paged=#{paged})" do
      path = File.join(@tmp, 'required-report.txt')
      File.write(path, 'accepted')
      status, report = cli_report('--execute', approved_plan(path, paged))
      expect(status).to eq(0)
      expect(report[:ok]).to be(true)
      expect(report[:results].map { |row| row[:id] }).to eq(%w[acceptance dependent])
      expect(acceptance_result(report, paged)).to include(success: true, passed: true)
      expect(checkpoints(report).map { |row| row[:status] }).to eq(%w[completed completed])
      expect(PWN::AI::Agent::Mission.resume_run(id: 'acceptance')).to include(ok: true, results: [])
      expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(true)
    end
  end

  it 'returns actual executable exit 1 on failed acceptance and exit 0 after a passing resume' do
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(@tmp, '.pwn', 'missions'))
    path = File.join(@tmp, 'required-report.txt')
    approval = approved_plan(path, true)
    preload = File.join(@tmp, 'offline-config.rb')
    File.write(preload, <<~RUBY)
      require 'pwn'
      PWN::Config.define_singleton_method(:refresh_env) { |_opts = {}| PWN::Env }
      PWN::Env[:ai] = { active: :ollama, module_reflection: false, agent: { artifact_max_tokens: 1024 } }
    RUBY
    command = [RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), '-r', preload, File.expand_path('../../bin/pwn-ai', __dir__)]
    stdout, stderr, status = Open3.capture3({ 'HOME' => @tmp }, *command, '--execute', approval, '--mission', 'acceptance', chdir: @tmp)
    expect(stderr).to be_empty
    expect(status.exitstatus).to eq(1)
    report = JSON.parse(stdout, symbolize_names: true)
    expect(report[:ok]).to be(false)
    expect(acceptance_result(report, true)).to include(success: false, passed: false)
    expect(checkpoints(report).map { |row| row[:status] }).to eq(['failed'])
    expect(PWN::AI::Agent::Mission.resume_run(id: 'acceptance')).to include(ok: false)
    expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(false)

    File.write(path, 'accepted')
    stdout, stderr, status = Open3.capture3({ 'HOME' => @tmp }, *command, '--resume', report[:run_id], '--mission', 'acceptance', chdir: @tmp)
    expect(stderr).to be_empty
    expect(status.exitstatus).to eq(0)
    resumed = JSON.parse(stdout, symbolize_names: true)
    expect(resumed[:results].map { |row| row[:id] }).to eq(%w[acceptance dependent])
    expect(acceptance_result(resumed, true)).to include(success: true, passed: true)
    expect(PWN::AI::Agent::Mission.resume_run(id: 'acceptance')).to include(ok: true, results: [])
    expect(PWN::AI::Agent::Mission.done?(id: 'acceptance')).to be(true)
  end

  it 'does not reinterpret an arbitrary tools passed field as the execution contract' do
    registry = PWN::AI::Agent::Registry
    entries = registry.instance_variable_get(:@entries).dup
    registry.register(name: 'eui_domain_data', toolset: 'test', schema: { parameters: { type: 'object' } },
                      handler: ->(_args) { { passed: false, description: 'domain data, not an acceptance verdict' } })
    response = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'eui_domain_data', arguments: '{}' } }), symbolize_names: true)
    expect(response).to include(success: true)
    expect(response[:result]).to include(passed: false)
  ensure
    registry.instance_variable_set(:@entries, entries)
  end
end
