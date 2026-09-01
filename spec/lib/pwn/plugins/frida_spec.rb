# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Frida do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'ssl_pinning_script returns injectable javascript' do
    js = described_class.ssl_pinning_script
    expect(js).to match(/SSL_CTX|TrustManager|pinning/i)
  end
end
