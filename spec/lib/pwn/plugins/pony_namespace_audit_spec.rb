# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Pony, 'mail builder regression' do
  it 'builds a plain text mail without attempting delivery' do
    mail = described_class.build_mail(to: 'fixture@example.invalid', body: 'offline body', via: :test)
    expect(mail.body.decoded).to eq('offline body')
  end

  it 'builds both body alternatives alongside an attachment' do
    mail = described_class.build_mail(to: 'fixture@example.invalid', body: 'offline body', html_body: '<p>offline body</p>', attachments: { 'fixture.txt' => 'data' }, via: :test)
    expect(mail.parts.first.mime_type).to eq('multipart/alternative')
    expect(mail.parts.first.parts.map(&:mime_type)).to contain_exactly('text/plain', 'text/html')
    expect(mail.attachments.first.decoded).to eq('data')
  end
end
