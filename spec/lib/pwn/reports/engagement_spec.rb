# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Reports::Engagement do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'writes html for two findings with poc paths' do
    Dir.mktmpdir do |dir|
      poc = File.join(dir, 'poc.rb')
      File.write(poc, 'puts 1')
      out = described_class.generate(
        engagement: 'lab',
        dir_path: dir,
        findings: [
          { title: 'a', severity: 'high', poc: poc },
          { title: 'b', severity: 'low', poc: poc }
        ]
      )
      expect(File.file?(out[:html])).to eq(true)
    end
  end
end
