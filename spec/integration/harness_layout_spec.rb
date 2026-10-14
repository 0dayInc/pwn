# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'harness fixture layout' do
  it 'packages test support and locked data without a parallel scripts suite' do
    root = File.expand_path('../..', __dir__)
    expect(File.directory?(File.join(root, 'scripts/harness'))).to be(false)
    spec = Gem::Specification.load(File.join(root, 'pwn.gemspec'))
    %w[spec/support/harness/evaluate.rb spec/support/harness/package_acceptance.rb spec/fixtures/harness/manifest.json].each do |path|
      expect(spec.files).to include(path)
      expect(File.file?(File.join(root, path))).to be(true)
    end
  end
end
