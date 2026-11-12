# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'rest-client'

RSpec.describe 'API import working-directory regression' do
  let(:specification) { { openapi: '3.0.3', info: { title: 'Fixture', version: '1' }, servers: [{ url: 'https://example.invalid' }], paths: {} } }

  around do |example|
    previous_dir = Dir.pwd
    Dir.mktmpdir('api-import-audit') do |dir|
      Dir.chdir(dir)
      FileUtils.mkdir_p('inputs')
      File.write('inputs/spec.json', JSON.generate(specification))
      example.run
    ensure
      Dir.chdir(previous_dir)
    end
  end

  it 'loads a relative Burp import without changing the caller directory' do
    mod = PWN::Plugins::BurpSuite
    allow(mod).to receive(:stop)
    allow(mod).to receive(:add_to_sitemap)
    cwd = Dir.pwd
    expect(mod.import_openapi_to_sitemap(burp_obj: {}, openapi_spec: 'inputs/spec.json')).to eq([])
    expect(Dir.pwd).to eq(cwd)
  end

  it 'keeps OpenAPI output paths relative to the caller directory' do
    allow(RestClient).to receive(:get).and_return('{"type":"object"}')
    cwd = Dir.pwd
    PWN::Plugins::OpenAPI.generate_spec(spec_paths: ['inputs/spec.json'], base_url: 'https://example.invalid', output_json_path: 'merged.json')
    expect(Dir.pwd).to eq(cwd)
    expect(File).to exist(File.join(cwd, 'merged.json'))
  end

  it 'sends an absolute ZAP import path without changing the caller directory' do
    mod = PWN::Plugins::Zaproxy
    allow(mod).to receive(:stop)
    allow(mod).to receive(:zap_rest_call).and_return(double('response', body: '{}'))
    cwd = Dir.pwd
    mod.import_openapi_to_sitemap(zap_obj: { api_key: 'fixture-token' }, openapi_spec: 'inputs/spec.json')
    expect(Dir.pwd).to eq(cwd)
    expect(mod).to have_received(:zap_rest_call).with(hash_including(params: hash_including(file: File.join(cwd, 'inputs/spec.json'))))
  end
end
