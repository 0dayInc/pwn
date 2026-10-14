# frozen_string_literal: true

require 'spec_helper'
require_relative '../support/harness/experiments'

# This exercises only the optional reference API, not a measured model-quality comparison.
RSpec.describe 'approved reference adapter observation', :harness_live do
  it 'retains the raw live response without treating it as verified success' do
    source = File.realpath(ENV.fetch('PWN_HARNESS_REFERENCE_SOURCE'))
    manifest = File.realpath(ENV.fetch('PWN_HARNESS_LIVE_MANIFEST'))
    prompt = File.realpath(ENV.fetch('PWN_HARNESS_PROMPT_FILE'))
    settings = HarnessExperiments.locked_json(manifest)
    HarnessEvaluation.validate_parity!(settings.fetch('pwn'), settings.fetch('reference'))
    expect(settings).to include('parity_reviewed' => true, 'provider_hard_cost_cap_confirmed' => true)
    expect(settings.fetch('approved_cost_usd')).to be > 0
    Dir.mktmpdir('pwn-live-reference-', '/tmp') do |root|
      output = File.join(root, 'response.json')
      env = { 'HOME' => root, 'PATH' => ENV.fetch('PATH'), 'LANG' => 'C.UTF-8', 'PWN_EVAL_API_KEY' => ENV.fetch('PWN_EVAL_API_KEY') }
      result = HarnessEvaluation.capture(env, ['python3', File.join(HarnessEvaluation::ROOT, 'spec/support/harness/reference_adapter.py'),
                                               '--approve-live', '--source', source, '--manifest', manifest, '--prompt-file', prompt, '--output', output],
                                         root, settings.fetch('reference').fetch('wall_seconds'))
      expect(result).to include(exit_status: 0, resource_cap: false)
      expect(JSON.parse(File.read(output))).to include('outcome' => 'UNVERIFIED', 'tokens' => nil, 'cost' => nil)
    end
  end
end
