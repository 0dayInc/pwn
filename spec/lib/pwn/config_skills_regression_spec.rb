# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Config skill catalog' do
  around do |example|
    Dir.mktmpdir('pwn-skill-catalog') do |root|
      @root = root
      example.run
    end
  end

  before { stub_const('PWN::Skills', {}) }

  def write_fixture(relative, content)
    path = File.join(@root, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, content)
    path
  end

  it 'reads CRLF frontmatter without changing the skill body' do
    body = "# Fixture\r\n\r\nKeep this body.\r\n"
    parsed = PWN::Config.parse_skill_frontmatter(content: "---\r\nname: fixture\r\ndescription: Fixture instructions\r\n---\r\n#{body}")
    expect(parsed[:frontmatter]).to include('name' => 'fixture', 'description' => 'Fixture instructions')
    expect(parsed[:body]).to eq(body)
  end

  it 'reports the root of the published catalog, even for an empty explicit override' do
    configured = File.join(@root, 'configured')
    stub_const('PWN::Env', { pwn_skills_path: configured })
    PWN::Config.load_skills
    expect(PWN::Config.active_skill_root).to eq(configured)

    catalog = Dir.chdir(@root) { PWN::Config.load_skills(pwn_skills_path: 'empty') }
    expect(catalog).to be_empty
    expect(PWN::Config.active_skill_root).to eq(File.join(@root, 'empty'))
    expect(PWN::Config.active_skill_root).to be_frozen
    expect(PWN::Env[:pwn_skills_path]).to eq(configured)

    stub_const('PWN::Skills', {})
    expect(PWN::Config.active_skill_root).to be_nil
    hide_const('PWN::Skills')
    expect(PWN::Config.active_skill_root).to be_nil
  end

  it 'does not run flat or nested Ruby on discovery or reload', :aggregate_failures do
    executed = []
    stub_const('SkillCatalogProbe', executed)
    source = "SkillCatalogProbe << __FILE__\n"
    write_fixture('guide/SKILL.md', "# Guide\n")

    # Use new paths on reload so Ruby's require cache cannot mask execution.
    %w[first second].each do |name|
      flat = write_fixture("#{name}.rb", source)
      helper = write_fixture("guide/scripts/#{name}.rb", source)
      skills = PWN::Config.load_skills(pwn_skills_path: @root)

      expect(executed).to be_empty
      expect(PWN::Skills).to equal(skills)
      expect(skills.fetch(name.to_sym)).to include(type: :ruby, format: :legacy, path: flat, content: source, loaded: false)
      expect(skills.fetch(:guide)).to include(type: :instruction, format: :agentskills)
      expect(File.read(flat)).to eq(source)
      expect(File.read(helper)).to eq(source)
    end
  end

  it 'indexes module instructions and references without resolving a helper dependency' do
    doc = "---\ndescription: Fixture guide\n---\n# Guide\n\n## References\n- references/note.md\n"
    entry = write_fixture('pwn/guide/SKILL.md', doc)
    write_fixture('pwn/guide/scripts/missing_dependency.rb', "require 'pwn_fixture_dependency_that_does_not_exist'\n")
    note = write_fixture('pwn/guide/references/note.md', "# Note\n")
    write_fixture('healthy/SKILL.md', "# Healthy\n")
    skills = PWN::Config.load_skills(pwn_skills_path: @root)

    guide = skills.fetch(:'pwn/guide')
    expect(guide).to include(type: :instruction, format: :module, description: 'Fixture guide', content: doc, references: ['references/note.md'])
    expect(guide).not_to have_key(:loaded)
    expect(guide).not_to have_key(:error)
    expect(File.read(entry)).to eq(doc)
    expect(File.read(note)).to eq("# Note\n")
    expect(skills.fetch(:healthy)).to include(type: :instruction)
  end

  it 'retains malformed flat Ruby as source alongside legacy Markdown' do
    source = "def fixture(\n"
    write_fixture('broken.rb', source)
    doc = "# Healthy\nFixture skill\n"
    write_fixture('healthy.md', doc)
    skills = PWN::Config.load_skills(pwn_skills_path: @root)

    expect(skills.fetch(:broken)).to include(type: :ruby, loaded: false, content: source)
    expect(skills.fetch(:broken)).not_to have_key(:error)
    expect(skills.fetch(:healthy)).to include(type: :instruction, format: :legacy, content: doc)
  end
end
