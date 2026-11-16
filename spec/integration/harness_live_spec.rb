# frozen_string_literal: true

require 'spec_helper'
require_relative '../support/harness/experiments'

# Live observation of the reference agent is not an rspec example. Specs stay
# in Ruby and do not launch python.
RSpec.describe 'approved reference adapter observation', :harness_live do
  it 'keeps the approval gate ahead of any reference import' do
    source = File.read(File.join(HarnessEvaluation::ROOT, 'spec/support/harness/reference_adapter.py'))
    main = source.split('def main():', 2).last
    expect(main.index('explicit --approve-live required')).to be < main.index('from run_agent import AIAgent')
    expect(main).to include('PWN_EVAL_API_KEY')
    expect(File.read(__FILE__)).not_to include('python3')
  end
end
