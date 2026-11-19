# frozen_string_literal: true

require 'spec_helper'
require 'json_schemer'

RSpec.describe 'json_schemer regexp_parser compatibility' do
  it 'loads and applies an ECMA pattern against the installed regexp_parser' do
    schema = JSONSchemer.schema({ 'type' => 'string', 'pattern' => '^a+$' }, regexp_resolver: 'ecma')
    expect(schema.valid?('aaa')).to be(true)
    expect(schema.valid?("a\na")).to be(false)
  end
end
