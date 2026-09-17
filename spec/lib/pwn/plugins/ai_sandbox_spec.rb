# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'json'
require 'tmpdir'

describe PWN::Plugins::AISandbox do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'denies rm -rf /tmp/fake_root in strict mode without touching disk' do
    root = '/tmp/fake_root'
    FileUtils.mkdir_p(root)
    marker = File.join(root, 'keep')
    File.write(marker, 'safe')
    begin
      out = described_class.exec(kind: :shell, payload: 'rm -rf /tmp/fake_root', mode: 'strict')
      expect(out[:error].to_s).to match(/sandbox violation/i)
      expect(File.file?(marker)).to be true
    ensure
      FileUtils.rm_rf(root)
    end
  end

  it 'denies FileUtils.rm_rf("/tmp/fake_root") in strict mode without touching disk' do
    root = '/tmp/fake_root'
    FileUtils.mkdir_p(root)
    marker = File.join(root, 'keep')
    File.write(marker, 'safe')
    begin
      out = described_class.exec(kind: :ruby, payload: "FileUtils.rm_rf('/tmp/fake_root')", mode: 'strict')
      expect(out[:error].to_s).to match(/sandbox violation/i)
      expect(File.file?(marker)).to be true
    ensure
      FileUtils.rm_rf(root)
    end
  end
end
