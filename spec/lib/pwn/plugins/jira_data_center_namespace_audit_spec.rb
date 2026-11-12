# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::JiraDataCenter, 'namespace audit regressions' do
  before do
    stub_const('PWN::Env', { plugins: { jira_data_center: { base_uri: 'https://jira.invalid/rest/api/2', token: 'fixture-token' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(PWN::Plugins::TTYSpinner).to receive_messages(start: nil, stop: nil)
  end

  %i[delete update].each do |action|
    it "rejects #{action} of a comment without its required identifier" do
      allow(described_class).to receive(:rest_call).and_return({})
      allow(described_class).to receive(:get_issue).and_return({})
      expect { described_class.issue_comment(issue: 'AUDIT-1', comment_action: action) }.to raise_error(RuntimeError, /comment_id/)
      expect(described_class).not_to have_received(:rest_call)
    end
  end

  it 'retries retrieving a newly created issue without creating it twice' do
    allow(described_class).to receive(:get_all_fields).and_return([{ name: 'Epic Name', id: 'customfield_1' }])
    expect(described_class).to receive(:rest_call).once.and_return(key: 'AUDIT-1')
    attempts = 0
    allow(described_class).to receive(:get_issue) do
      attempts += 1
      raise 'not ready yet' if attempts == 1

      { key: 'AUDIT-1' }
    end
    allow(described_class).to receive(:sleep)
    expect(described_class.create_issue(project_key: 'AUDIT', summary: 'offline fixture', issue_type: :bug)).to include(key: 'AUDIT-1')
    expect(attempts).to eq(2)
  end

  it 'uses the issue key returned in a successful HTTP 201 creation response' do
    response = RestClient::Response.create('{"key":"AUDIT-1"}', Net::HTTPResponse.new('1.1', '201', 'Created'), RestClient::Request.new(method: :post, url: 'https://jira.invalid/rest/api/2/issue'))
    allow(RestClient::Request).to receive(:execute).and_return(response)
    allow(described_class).to receive(:get_all_fields).and_return([{ name: 'Epic Name', id: 'customfield_1' }])
    expect(described_class).to receive(:get_issue).with(issue: 'AUDIT-1').and_return(key: 'AUDIT-1')
    expect(described_class.create_issue(project_key: 'AUDIT', summary: 'offline fixture', issue_type: :bug)).to include(key: 'AUDIT-1')
  end
end
