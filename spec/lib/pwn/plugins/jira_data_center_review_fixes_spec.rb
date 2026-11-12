# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::JiraDataCenter, 'review creation error regressions' do
  def response(body, code = 200)
    RestClient::Response.create(body, Net::HTTPResponse.new('1.1', code.to_s, 'Fixture'),
                                RestClient::Request.new(method: :get, url: 'https://jira.invalid/'))
  end

  before do
    stub_const('PWN::Env', { plugins: { jira_data_center: { base_uri: 'https://jira.invalid/rest/api/2', token: 'fixture' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(PWN::Plugins::TTYSpinner).to receive_messages(start: nil, stop: nil)
    allow(described_class).to receive(:sleep)
  end

  ['{"errors":{"summary":"invalid"}}', '{"errorMessages":["forbidden"]}', '[]', '<html>rejected</html>', ''].each do |body|
    it "PSR-L06 propagates the original nonretryable HTTP creation failure #{body.inspect}" do
      error = RestClient::BadRequest.new(response(body, 400))
      creates = 0
      allow(RestClient::Request).to receive(:execute) do |request|
        next response('[{"name":"Epic Name","id":"customfield_1"}]') if request[:url].end_with?('/field')

        expect(request[:method]).to eq(:post)
        creates += 1
        raise error
      end
      expect do
        described_class.create_issue(project_key: 'AUDIT', summary: 'fixture', issue_type: :bug)
      end.to(raise_error { |raised| expect(raised).to equal(error) })
      expect(creates).to eq(1)
    end
  end

  it 'retains a single HTTP 201 create and retries actual HTTP 404 readback' do
    reads = 0
    creates = 0
    allow(RestClient::Request).to receive(:execute) do |request|
      case request[:url]
      when %r{/field\z}
        response('[{"name":"Epic Name","id":"customfield_1"}]')
      when %r{/issue\z}
        creates += 1
        response('{"key":"AUDIT-1"}', 201)
      when %r{/issue/AUDIT-1\z}
        reads += 1
        raise RestClient::NotFound, response('{"errorMessages":["not visible yet"]}', 404) if reads == 1

        response('{"key":"AUDIT-1"}')
      else
        raise "Unexpected fixture URL: #{request[:url]}"
      end
    end
    result = described_class.create_issue(project_key: 'AUDIT', summary: 'fixture', issue_type: :bug)
    expect([result, creates, reads]).to eq([{ key: 'AUDIT-1' }, 1, 2])
  end

  it 'retains bounded unlicensed-field recovery through the actual REST helper' do
    creates = []
    allow(RestClient::Request).to receive(:execute) do |request|
      case request[:url]
      when %r{/field\z} then response('[{"name":"Epic Name","id":"customfield_1"}]')
      when %r{/issue/AUDIT-1\z} then response('{"key":"AUDIT-1"}')
      when %r{/issue\z}
        creates << JSON.parse(request[:payload])
        raise RestClient::BadRequest, response('{"errors":{"customfield_2":"unlicensed"}}', 400) if creates.length == 1

        response('{"key":"AUDIT-1"}', 201)
      else raise "Unexpected fixture URL: #{request[:url]}"
      end
    end
    result = described_class.create_issue(project_key: 'AUDIT', summary: 'fixture', issue_type: :bug,
                                          additional_fields: { fields: { 'customfield_2' => 'fixture' } })
    expect(result).to eq(key: 'AUDIT-1')
    expect(creates.length).to eq(2)
    expect(creates.first.fetch('fields')).to include('customfield_2' => 'fixture')
    expect(creates.last.fetch('fields')).not_to have_key('customfield_2')
  end
end
