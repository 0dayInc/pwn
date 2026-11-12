# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::SAST::SQL, 'candidate preservation' do
  around do |example|
    Dir.mktmpdir('pwn-sql-review-') do |dir|
      @sources = dir
      example.run
    end
  end

  before { stub_const('PWN::Env', { ai: { module_reflection: false } }) }

  candidates = [
    %q{db.execute("SELECT name FROM users WHERE name = '" + user_input + "' AND email LIKE '%@example.invalid'")},
    'db.execute("SELECT name FROM users WHERE id = " + params[:x])',
    'db.execute("SELECT name FROM users WHERE id = ? ORDER BY " + sort, [id])',
    'db.execute("SELECT name FROM users WHERE id = :id ORDER BY " + sort, id: id)',
    'db.execute("SELECT name FROM users WHERE id = $1 ORDER BY " + sort, [id])',
    'db.execute("SELECT name FROM users WHERE id = :1 ORDER BY " + sort, [id])'
  ]
  candidates.each_with_index do |source, index|
    [1, 11].each do |line|
      it "SERVICES-REVIEW-003 retains dynamic SQL candidate #{index} on line #{line} despite placeholder punctuation" do
        File.write(File.join(@sources, 'source.rb'), "#{"\n" * (line - 1)}#{source}\n")
        options = { dir_path: @sources }.freeze

        result = described_class.scan(options)

        expect(result.length).to eq(1)
        expect(result.first[:line_no_and_contents]).to contain_exactly(include(line_no: line.to_s, contents: "#{source}\n"))
        expect(options).to eq(dir_path: @sources)
      end
    end
  end
end
