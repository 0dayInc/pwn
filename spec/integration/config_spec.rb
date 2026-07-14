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
end
