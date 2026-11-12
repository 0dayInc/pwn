# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Pony, 'review Unicode MIME roundtrip' do
  [false, true].each do |with_attachment|
    it "preserves explicit UTF-8 charset and MIME types (attachment: #{with_attachment})" do
      opts = { to: 'fixture@example.invalid', body: 'café 日本語 ☃', html_body: '<p>café 日本語 ☃</p>',
               charset: 'UTF-8', text_part_charset: 'UTF-8', via: :test }
      opts[:attachments] = { 'fixture.bin' => "\x00\xff\n".b } if with_attachment
      parsed = Mail.read_from_string(described_class.build_mail(opts).encoded)
      alternatives = with_attachment ? parsed.parts.first : parsed
      expect(alternatives.text_part.mime_type).to eq('text/plain')
      expect(alternatives.text_part.decoded).to eq(opts[:body])
      expect(alternatives.html_part.decoded).to eq(opts[:html_body])
      expect(alternatives.text_part.charset).to eq('UTF-8')
      expect(parsed.attachments.first.decoded.b).to eq("\x00\xff\n".b) if with_attachment
    end

    it "preserves Unicode text and HTML through Mail serialization (attachment: #{with_attachment})" do
      opts = { to: 'fixture@example.invalid', body: 'café 日本語 ☃', html_body: '<p>café 日本語 ☃</p>', via: :test }
      opts[:attachments] = { 'fixture.bin' => "\x00\xff\n".b } if with_attachment
      parsed = Mail.read_from_string(described_class.build_mail(opts).encoded)
      alternatives = with_attachment ? parsed.parts.first : parsed
      expect(alternatives.mime_type).to eq('multipart/alternative')
      expect(alternatives.text_part.decoded).to eq(opts[:body])
      expect(alternatives.html_part.decoded).to eq(opts[:html_body])
      expect(alternatives.text_part.charset).to eq('UTF-8')
      expect(alternatives.html_part.charset).to eq('UTF-8')
      expect(parsed.attachments.first.decoded.b).to eq("\x00\xff\n".b) if with_attachment
    end
  end
end
