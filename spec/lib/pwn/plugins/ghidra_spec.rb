# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Ghidra do
  it 'degrades with a hint when analyzeHeadless and r2 are missing' do
    allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_return(false)
    path = %w[/bin/true /usr/bin/true].find { |p| File.file?(p) }
    skip 'no binary' unless path

    row = described_class.analyze(bin: path)
    expect(row[:error].to_s).to match(/missing/i)
  end
end
