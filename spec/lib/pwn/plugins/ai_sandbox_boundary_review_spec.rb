# frozen_string_literal: true

require 'spec_helper'
require 'digest'

RSpec.describe 'AISandbox mandatory write-grant review' do
  include_context 'pwn tmp sandbox'

  before do
    @home = File.join(@tmp, 'home')
    @work = File.join(@tmp, 'work')
    @outputs = File.join(@tmp, 'outputs')
    @source = File.join(@outputs, 'source')
    @state = File.join(@outputs, 'controller-artifacts')
    FileUtils.mkdir_p([@home, @work, @source, @state])
    allow(Dir).to receive(:home).and_return(@home)
    allow(PWN::Plugins::AISandbox).to receive(:protected_roots).and_return([@source, '/opt/pwn'])
    stub_const('PWN::Plugins::ArtifactRegistry::ROOT', @state)
    @saved_runtime = Thread.current[:pwn_request_runtime]
    @source_file = File.join(@source, 'sentinel')
    @state_file = File.join(@state, 'sentinel')
    File.write(@source_file, 'original-source')
    File.write(@state_file, 'original-state')
  end

  after do
    Thread.current[:pwn_request_runtime] = @saved_runtime
  end

  def dispatch_boundary(request, &handler)
    runtime = PWN::AI::Agent::RequestRuntime.new(request: request, session_id: 'sandbox-review', artifact_root: File.join(@tmp, 'request-state'), cwd: @work, trace: false, retrieve: false)
    Thread.current[:pwn_request_runtime] = runtime
    PWN::AI::Agent::Registry.register(name: 'sandbox_pbr01_boundary', toolset: 'fixture', schema: { name: 'sandbox_pbr01_boundary', parameters: { type: 'object' } }, handler: handler)
    row = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'sandbox_pbr01_boundary', arguments: '{}' } }))
    [row, runtime]
  end

  it '[PBR-01] denies source and controller writes despite an original-request sibling output', :aggregate_failures do
    output = File.join(@outputs, 'requested.txt')
    before = [@source_file, @state_file].to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
    row, runtime = dispatch_boundary("Write the report to #{output}") do |_args|
      attempts = [@source_file, @state_file].map do |path|
        File.write(path, 'modified')
        'allowed'
      rescue Errno::EACCES, Errno::EPERM
        'denied'
      end
      File.write(output, 'named')
      { attempts: attempts, named: File.read(output) }
    end
    expect(runtime.contract[:required_artifacts]).to eq([output])
    expect(row.dig('result', 'attempts')).to eq(%w[denied denied])
    expect(row.dig('result', 'named')).to eq('named')
    expect([@source_file, @state_file].to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }).to eq(before)
    expect(File.read(output)).to eq('named')
  end
end
