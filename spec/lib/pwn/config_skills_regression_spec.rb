# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Config skill loading failures' do
  include_context 'pwn tmp sandbox'

  before { stub_const('PWN::Skills', {}) }

  it 'reads CRLF frontmatter without changing the skill body' do
    body = "# Fixture\r\n\r\nKeep this body.\r\n"
    parsed = PWN::Config.parse_skill_frontmatter(content: "---\r\nname: fixture\r\ndescription: Fixture instructions\r\n---\r\n#{body}")
    expect(parsed[:frontmatter]).to include('name' => 'fixture', 'description' => 'Fixture instructions')
    expect(parsed[:body]).to eq(body)
  end

  it 'reports a broken directory skill without aborting the remaining catalog' do
    bad = File.join(@tmp, 'skills', 'broken', 'scripts')
    good = File.join(@tmp, 'skills', 'healthy')
    FileUtils.mkdir_p([bad, good])
    File.write(File.join(File.dirname(bad), 'SKILL.md'), "# Broken\nFixture skill\n")
    File.write(File.join(bad, 'missing_dependency.rb'), "require 'pwn_fixture_dependency_that_does_not_exist'\n")
    File.write(File.join(good, 'SKILL.md'), "# Healthy\nFixture skill\n")
    skills = PWN::Config.load_skills(pwn_skills_path: File.join(@tmp, 'skills'))
    expect(skills[:broken]).to include(loaded: false)
    expect(skills[:broken][:error]).to include('pwn_fixture_dependency_that_does_not_exist')
    expect(skills).to have_key(:healthy)
  end

  it 'reports legacy Ruby syntax failures without aborting the catalog' do
    File.write(File.join(@tmp, 'broken.rb'), "def fixture(\n")
    File.write(File.join(@tmp, 'healthy.md'), "# Healthy\nFixture skill\n")
    skills = PWN::Config.load_skills(pwn_skills_path: @tmp)
    expect(skills[:broken]).to include(loaded: false)
    expect(skills[:broken][:error]).not_to be_empty
    expect(skills).to have_key(:healthy)
  end
end
