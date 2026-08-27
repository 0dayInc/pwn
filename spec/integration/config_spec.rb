# frozen_string_literal: true

require 'spec_helper'
require 'yaml'

# ─────────────────────────────────────────────────────────────────────────────
#  #11 — configuration & example-YAML hygiene. NON-BLOCKING: filesystem
#  reads + YAML.safe_load only; nothing decrypts, nothing touches ~/.pwn.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::Config / etc/*.EXAMPLE hygiene', :aggregate_failures do
  root = File.expand_path('../..', __dir__)

  describe 'etc/**/*.{yaml,yml}.EXAMPLE parse cleanly under YAML.safe_load' do
    Dir[File.join(root, 'etc', '**', '*.{yaml,yml}.EXAMPLE')].each do |f|
      it File.join('etc', f.delete_prefix("#{root}/etc/")) do
        expect do
          YAML.safe_load_file(f, permitted_classes: [Symbol, Date, Time], aliases: true)
        end.not_to raise_error
      end
    end
  end

  it 'PWN::Env is a Hash and .dig on a non-existent path returns nil (never raises)' do
    expect(PWN::Env).to be_a(Hash)
    expect(PWN::Env.dig(:does, :not, :exist)).to be_nil
    expect { PWN::Env.dig(:ai, :agent, :nope, :nada) }.not_to raise_error
  end

  it 'PWN::Config.load_skills honours an explicit path and does not touch ~/.pwn' do
    Dir.mktmpdir('pwn_skills_spec') do |dir|
      File.write(File.join(dir, 'probe.md'), "# probe skill\nbody\n")
      prev = defined?(PWN::Skills) ? PWN::Skills : nil
      skills = PWN::Config.load_skills(pwn_skills_path: dir)
      expect(skills.keys.map(&:to_sym)).to include(:probe)
      expect(skills[:probe][:type]).to eq(:instruction)
      expect(PWN::Skills).to eq(skills)
    ensure
      PWN.send(:remove_const, :Skills) if PWN.const_defined?(:Skills)
      PWN.const_set(:Skills, prev.freeze) if prev
    end
  end

  it 'PWN::Config.load_skills reads agentskills.io <name>/SKILL.md with frontmatter' do
    Dir.mktmpdir('pwn_skills_spec') do |dir|
      prev = defined?(PWN::Skills) ? PWN::Skills : nil
      out  = PWN::Config.write_skill(name: 'cfg-probe', description: 'cfg probe desc', content: "step\n", pwn_skills_path: dir)
      expect(File.basename(out[:path])).to eq('SKILL.md')
      expect(File.basename(File.dirname(out[:path]))).to eq('cfg-probe')
      skills = PWN::Config.load_skills(pwn_skills_path: dir)
      expect(skills[:'cfg-probe'][:format]).to eq(:agentskills)
      expect(skills[:'cfg-probe'][:description]).to eq('cfg probe desc')
      expect(skills[:'cfg-probe'][:frontmatter]['name']).to eq('cfg-probe')
    ensure
      PWN.send(:remove_const, :Skills) if PWN.const_defined?(:Skills)
      PWN.const_set(:Skills, prev.freeze) if prev
    end
  end

  it 'PWN::Setup::PROFILES is well-formed (every profile has :desc, :gems, :bins)' do
    PWN::Setup::PROFILES.each do |name, meta|
      expect(meta).to include(:desc, :gems, :bins), "profile :#{name} missing keys"
      expect(meta[:gems]).to be_an(Array)
      expect(meta[:bins]).to be_an(Array)
    end
    expect(PWN::Setup::PROFILES).to include(:core, :full)
  end

  it 'install_default_skills seeds the bundled offensive skills and does not overwrite edits' do
    Dir.mktmpdir('pwn_default_skills') do |dir|
      expect(PWN::Config).to respond_to(:install_default_skills)
      expect(PWN::Config).to respond_to(:default_skill_names)
      names = PWN::Config.default_skill_names
      expect(names).to eq %w[
        vulnerability-research-fundamentals
        deep-exploitation
        bug-bounty-hunting
        sast-code-scans
        reverse-engineering-binaries
        penetration-testing
        web-application-penetration-testing
        red-teaming
        hardware-and-firmware-testing
        social-engineering
        osint
        cwe
        capec
        att&ck
      ]
      seeded = PWN::Config.install_default_skills(pwn_skills_path: dir)
      expect(seeded.map { |r| r[:name] }).to match_array(names)
      names.each do |name|
        path = File.join(dir, name, 'SKILL.md')
        expect(File.file?(path)).to eq(true), path
        body = File.read(path)
        expect(body).to start_with("---\n")
        expect(body).to match(/name:\s*"?#{Regexp.escape(name)}"?/)
        expect(body).not_to match(/hermes/i)
        expect(body).to match(/## Methodolog/i)
      end
      marker = File.join(dir, 'bug-bounty-hunting', 'SKILL.md')
      File.write(marker, "# user edited\n")
      again = PWN::Config.install_default_skills(pwn_skills_path: dir)
      expect(again).to eq([])
      expect(File.read(marker)).to eq("# user edited\n")
      cwe_ref = File.join(dir, 'cwe', 'references', 'CWE-79.md')
      expect(File.file?(cwe_ref)).to eq(true), cwe_ref
      expect(File.read(cwe_ref)).to include('CWE-79')
      expect(File.read(cwe_ref)).to match(/Exhaustive test/i)
      expect(File.read(cwe_ref)).not_to match(/hermes/i)
      capec_ref = File.join(dir, 'capec', 'references', 'CAPEC-66.md')
      expect(File.file?(capec_ref)).to eq(true), capec_ref
      expect(File.read(capec_ref)).to include('CAPEC-66')
      expect(File.read(capec_ref)).to match(/Exhaustive test/i)
      expect(File.read(capec_ref)).not_to match(/hermes/i)
      att_ref = File.join(dir, 'att&ck', 'references', 'T1059.001.md')
      expect(File.file?(att_ref)).to eq(true), att_ref
      expect(File.read(att_ref)).to include('T1059.001')
      expect(File.read(att_ref)).to match(/Exhaustive test/i)
      expect(File.read(att_ref)).not_to match(/hermes/i)
      gw = File.join(dir, 'pwn', 'plugins', 'google_workspace', 'SKILL.md')
      expect(File.file?(gw)).to eq(true), gw
      expect(File.read(gw)).to include('PWN::Plugins::GoogleWorkspace')
      expect(File.read(gw)).to include('gmail_search')
      expect(File.read(gw)).not_to match(/hermes/i)
      expect(File).not_to exist(File.join(dir, 'productivity', 'google-workspace', 'SKILL.md'))
      expect(File).not_to exist(File.join(dir, 'google-workspace', 'SKILL.md'))
      gw_ref = File.join(dir, 'pwn', 'plugins', 'google_workspace', 'references', 'gmail-search-syntax.md')
      expect(File.file?(gw_ref)).to eq(true), gw_ref
    end
  end

  it 'installs every SKILL.md under default_skills recursively and load_skills indexes nested dirs' do
    Dir.mktmpdir('pwn_nested_skills') do |dir|
      src = File.join(dir, 'src')
      dest = File.join(dir, 'skills')
      nested = File.join(src, 'research', 'nested-probe')
      FileUtils.mkdir_p(File.join(nested, 'references', 'deep'))
      File.write(
        File.join(nested, 'SKILL.md'),
        "---\nname: nested-probe\ndescription: nested probe desc\n---\n# Nested\n"
      )
      File.write(File.join(nested, 'references', 'deep', 'note.md'), "# note\n")
      FileUtils.mkdir_p(File.join(nested, 'scripts'))
      File.write(File.join(nested, 'scripts', 'skip.rb'), "# helper\n")
      seeded = PWN::Config.install_default_skills(pwn_skills_path: dest, source: src)
      expect(seeded.map { |r| r[:name] }).to include('research/nested-probe')
      expect(File.file?(File.join(dest, 'research', 'nested-probe', 'SKILL.md'))).to eq(true)
      expect(File.file?(File.join(dest, 'research', 'nested-probe', 'references', 'deep', 'note.md'))).to eq(true)
      expect(File).not_to exist(File.join(dest, 'research', 'nested-probe', 'scripts', 'skip.rb'))
      prev = defined?(PWN::Skills) ? PWN::Skills : nil
      skills = PWN::Config.load_skills(pwn_skills_path: dest)
      expect(skills.keys.map(&:to_s)).to include('research/nested-probe')
      expect(skills[:'research/nested-probe'][:description]).to eq('nested probe desc')
    ensure
      PWN.send(:remove_const, :Skills) if PWN.const_defined?(:Skills)
      PWN.const_set(:Skills, prev.freeze) if prev
    end
  end
end
