# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Jenkins, 'connection defaults regression' do
  it 'passes the documented port and TLS defaults to the client' do
    service = instance_double(JenkinsApi::Client::System, wait_for_ready: true)
    client = instance_double(JenkinsApi::Client, system: service)
    expect(JenkinsApi::Client).to receive(:new).with(hash_including(server_ip: 'jenkins.invalid', server_port: 8080, ssl: true)).and_return(client)
    expect(described_class.connect(ip: 'jenkins.invalid')).to eq(client)
  end
end
