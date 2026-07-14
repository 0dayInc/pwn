# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools skills' do
  before(:all) { PWN::AI::Agent::Registry.discover }

  it 'registers the skill_list tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'skill_list')).not_to be_nil
  end

  it 'registers the skill_migrate_legacy tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'skill_migrate_legacy')).not_to be_nil
  end

  describe 'agentskills.io conformance' do
    before do
      @prev = defined?(PWN::Skills) ? PWN::Skills : nil
      @root = Dir.mktmpdir('pwn_skills_tool_spec')
      allow(PWN::Config).to receive(:pwn_skills_path).and_return(@root)
    end

    after do
      FileUtils.rm_rf(@root) if @root
      PWN.send(:remove_const, :Skills) if PWN.const_defined?(:Skills)
      PWN.const_set(:Skills, @prev.freeze) if @prev
    end

    let(:create) { PWN::AI::Agent::Registry.lookup(name: 'skill_create')[:handler] }
    let(:addref) { PWN::AI::Agent::Registry.lookup(name: 'skill_add_reference')[:handler] }
    let(:delete) { PWN::AI::Agent::Registry.lookup(name: 'skill_delete')[:handler] }
    let(:list)   { PWN::AI::Agent::Registry.lookup(name: 'skill_list')[:handler] }
    let(:view)   { PWN::AI::Agent::Registry.lookup(name: 'skill_view')[:handler] }

    it 'skill_create writes <name>/SKILL.md with required name+description frontmatter' do
      out = create.call(name: 'Recon Quick_Scan', description: 'Fast host triage.', content: "# Recon\nnmap -T4 -F {t}\n", references: ['T1046'])
      expect(out[:saved]).to be true
      expect(out[:name]).to eq('recon-quick-scan')
      expect(out[:path]).to eq(File.join(@root, 'recon-quick-scan', 'SKILL.md'))
      expect(File).to exist(out[:path])

      fm = PWN::Config.parse_skill_frontmatter(content: File.read(out[:path]))[:frontmatter]
      expect(fm['name']).to eq('recon-quick-scan')
      expect(fm['description']).to eq('Fast host triage.')
      expect(fm.dig('metadata', 'references')).to include('T1046')
    end

    it 'skill_create derives description from body when omitted' do
      out = create.call(name: 'no-desc', content: "# Heading\nFirst real line becomes the description.\n")
      fm  = PWN::Config.parse_skill_frontmatter(content: File.read(out[:path]))[:frontmatter]
      expect(fm['description']).to eq('First real line becomes the description.')
    end

    it 'sanitises names to [a-z0-9-]{1,64} with no edge/double hyphens' do
      expect(PWN::Config.sanitize_skill_name(name: '__Foo  Bar__')).to eq('foo-bar')
      expect(PWN::Config.sanitize_skill_name(name: '-a--b-')).to eq('a-b')
      expect(PWN::Config.sanitize_skill_name(name: 'x' * 200).length).to be <= 64
      expect { PWN::Config.sanitize_skill_name(name: '!!!') }.to raise_error(ArgumentError)
    end

    it 'skill_add_reference rewrites frontmatter metadata.references on an agentskills entry' do
      create.call(name: 'ref-skill', description: 'd', content: "body\n", references: ['CWE-79'])
      res = addref.call(name: 'ref-skill', references: %w[CWE-89 CWE-79])
      expect(res[:added]).to eq(['CWE-89'])
      expect(res[:references]).to include('CWE-79', 'CWE-89')
      fm = PWN::Config.parse_skill_frontmatter(content: File.read(res[:path]))[:frontmatter]
      expect(fm.dig('metadata', 'references')).to include('CWE-79', 'CWE-89')
    end

    it 'skill_delete removes the whole skill directory' do
      out = create.call(name: 'doomed', description: 'd', content: "body\n")
      dir = File.dirname(out[:path])
      expect(Dir).to exist(dir)
      delete.call(name: 'doomed')
      expect(Dir).not_to exist(dir)
    end

    it 'skill_list / skill_view surface description and format' do
      create.call(name: 'listed', description: 'Shows in the index.', content: "body\n")
      row = list.call({}).find { |r| r[:name] == :listed }
      expect(row[:description]).to eq('Shows in the index.')
      expect(row[:format]).to eq(:agentskills)
      v = view.call(name: 'listed')
      expect(v[:description]).to eq('Shows in the index.')
      expect(v[:frontmatter]['name']).to eq('listed')
    end

    it 'still loads legacy flat *.md alongside directory skills' do
      File.write(File.join(@root, 'oldflat.md'), "# Old\nlegacy body\n")
      create.call(name: 'newdir', description: 'd', content: "body\n")
      sk = PWN::Config.load_skills(pwn_skills_path: @root)
      expect(sk[:oldflat][:format]).to eq(:legacy)
      expect(sk[:newdir][:format]).to eq(:agentskills)
    end
  end
end
