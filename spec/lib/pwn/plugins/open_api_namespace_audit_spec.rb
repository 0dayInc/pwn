# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::OpenAPI, 'root path regression' do
  it 'retains a root endpoint when normalizing server path prefixes' do
    Dir.mktmpdir('openapi-audit') do |dir|
      source = File.join(dir, 'input.json')
      output = File.join(dir, 'output.json')
      File.write(source, JSON.generate(openapi: '3.0.3', info: { title: 'Fixture', version: '1' }, paths: { '/' => { get: { responses: { '200' => { description: 'OK' } } } } }))
      allow(RestClient).to receive(:get).and_return('{"type":"object"}')
      previous_dir = Dir.pwd
      begin
        described_class.generate_spec(spec_paths: [source], base_url: 'https://example.invalid', output_json_path: output)
        expect(JSON.parse(File.read(output))['paths']).to have_key('/')
      ensure
        Dir.chdir(previous_dir)
      end
    end
  end
end
