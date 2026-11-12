# frozen_string_literal: true

require 'spec_helper'
require 'aws-sdk'

RSpec.describe 'AWS service runtime regressions' do
  before do
    allow(Aws).to receive(:shared_config).and_return(
      Aws::SharedConfig.new(config_enabled: false, credentials_path: File::NULL, config_path: File::NULL)
    )
    allow(Aws).to receive(:config).and_return(stub_responses: true)
  end

  (PWN::AWS.constants(false) - [:STS]).sort.each do |name|
    [nil, 'fixture-session'].each do |token|
      it "constructs #{name} with #{token ? 'temporary' : 'static'} credentials using the installed SDK" do
        sdk_name = name == :Workspaces ? :WorkSpaces : name
        sdk_class = Aws.const_get(sdk_name)::Client
        options = {
          region: 'us-east-1', access_key_id: 'fixture-access', secret_access_key: 'fixture-secret',
          sts_session_token: token
        }
        options[:endpoint] = 'https://search-fixture.us-east-1.cloudsearch.amazonaws.com' if name == :CloudSearchDomain
        client = PWN::AWS.const_get(name).connect(options)
        expect(client).to be_a(sdk_class)
        expect(client.config.access_key_id).to eq('fixture-access')
        expect(client.config.secret_access_key).to eq('fixture-secret')
        expect(client.config.session_token).to eq(token)
        expect(client.config.endpoint.to_s).to eq(options[:endpoint]) if options[:endpoint]
      end
    end
  end

  it 'preserves an SDK-configured CloudSearch endpoint when no wrapper override is supplied' do
    endpoint = 'https://search-fixture.us-east-1.cloudsearch.amazonaws.com'
    allow(Aws).to receive(:config).and_return(stub_responses: true, endpoint: endpoint)
    client = PWN::AWS::CloudSearchDomain.connect(region: 'us-east-1', access_key_id: 'fixture-access', secret_access_key: 'fixture-secret')
    expect(client.config.endpoint.to_s).to eq(endpoint)
  end

  it 'returns the STS credentials and forwards assume-role arguments to a stubbed SDK client' do
    client = Aws::STS::Client.new(region: 'us-east-1', credentials: Aws::Credentials.new('fixture-access', 'fixture-secret'), stub_responses: true)
    client.stub_responses(:assume_role, credentials: {
                            access_key_id: 'fixture-temporary', secret_access_key: 'fixture-secret', session_token: 'fixture-token', expiration: Time.utc(2030, 1, 1)
                          })
    allow(Aws::STS::Client).to receive(:new).with(region: 'us-east-1').and_return(client)
    result = PWN::AWS::STS.get_temp_credentials(region: 'us-east-1', role_arn: 'arn:aws:iam::123456789012:role/fixture', role_session_name: 'fixture', duration_seconds: 900)
    expect(result.access_key_id).to eq('fixture-temporary')
    expect(client.api_requests.last[:params]).to eq(role_arn: 'arn:aws:iam::123456789012:role/fixture', role_session_name: 'fixture', duration_seconds: 900)
  end
end
