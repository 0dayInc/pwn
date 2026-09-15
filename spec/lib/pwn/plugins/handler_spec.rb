# frozen_string_literal: true

require 'spec_helper'
require 'socket'

describe PWN::Plugins::Handler do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'generates a reverse shell payload without Metasploit' do
    row = described_class.generate(kind: 'rev_sh', host: '127.0.0.1', port: 4444)
    expect(row[:payload]).to include('127.0.0.1')
    expect(row[:payload]).to include('4444')
  end

  it 'generates bind python and powershell payloads' do
    expect(described_class.generate(kind: 'bind_python', port: 5555)[:payload]).to include('5555')
    expect(described_class.generate(kind: 'bind_powershell', port: 5555)[:payload]).to include('GetStream')
  end
end
