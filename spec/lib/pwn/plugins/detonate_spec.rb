# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Detonate do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'refuses when isolation preconditions are unmet' do
    Dir.mktmpdir do |dir|
      sample = File.join(dir, 's.bin')
      File.write(sample, 'MZ')
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'podman').and_return(false)
      row = described_class.detonate(path: sample)
      expect(row[:error].to_s).to match(/isolation/)
    end
  end
end
