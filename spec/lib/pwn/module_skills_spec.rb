# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'

describe PWN::ModuleSkills do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'maps a constant or source file to a namespace-mirrored SKILL.md path' do
    expect(described_class.relpath(const: 'PWN::Plugins::TransparentBrowser')).to eq(
      'pwn/plugins/transparent_browser/SKILL.md'
    )
    expect(described_class.relpath(source: 'pwn/plugins/baresip.rb')).to eq(
      'pwn/plugins/baresip/SKILL.md'
    )
    expect(described_class.relpath(source: 'pwn.rb')).to eq('pwn/SKILL.md')
  end

  it 'refreshes etc/default_skills/pwn from every lib/pwn module' do
    report = described_class.refresh!
    expect(report[:modules]).to be > 50
    tb = File.join(PWN::ModuleSkills::GEM_SKILLS, 'plugins', 'transparent_browser', 'SKILL.md')
    expect(File.file?(tb)).to eq(true), tb
    expect(File).not_to exist(File.join(PWN::ModuleSkills::GEM_SKILLS, 'plugins', 'transparent_browser.md'))
    body = File.read(tb)
    expect(body).to include('PWN::Plugins::TransparentBrowser')
    expect(body).to include('open')
    expect(body).not_to match(/hermes/i)

    pw = File.join(PWN::ModuleSkills::GEM_SKILLS, 'sast', 'password', 'SKILL.md')
    expect(File.file?(pw)).to eq(true), pw
    expect(File.file?(File.join(PWN::ModuleSkills::GEM_SKILLS, 'sast', 'password', 'references', 'security.md'))).to eq(true)

    gw = File.join(PWN::ModuleSkills::GEM_SKILLS, 'plugins', 'google_workspace', 'SKILL.md')
    expect(File.read(gw)).to include('preserve: true')
    expect(File.read(gw)).to include('gmail_search')
    expect(File.read(gw)).to include('daily-brief.md')
    expect(File).not_to exist(File.join(PWN::Config.default_skills_dir, 'productivity', 'google-workspace', 'SKILL.md'))

    described_class.enumerate.each do |rec|
      path = File.join(
        File.dirname(PWN::ModuleSkills::GEM_SKILLS),
        described_class.relpath(source: rec[:source], const: rec[:const])
      )
      expect(File.file?(path)).to eq(true), path
      expect(File.read(path)).to include(rec[:const])
      expect(File.read(path)).not_to match(/hermes/i)
    end
  end

  it 'install overwrites existing generated module skills' do
    Dir.mktmpdir('pwn_mod_skills') do |dir|
      src = File.join(dir, 'src', 'plugins', 'transparent_browser')
      dest = File.join(dir, 'skills')
      FileUtils.mkdir_p(src)
      File.write(File.join(src, 'SKILL.md'), "# v1\n")
      described_class.install(pwn_skills_path: dest, source: File.join(dir, 'src'))
      target = File.join(dest, 'pwn', 'plugins', 'transparent_browser', 'SKILL.md')
      expect(File.read(target)).to eq("# v1\n")
      File.write(File.join(src, 'SKILL.md'), "# v2\n")
      described_class.install(pwn_skills_path: dest, source: File.join(dir, 'src'))
      expect(File.read(target)).to eq("# v2\n")
    end
  end

  it 'ships no credential-shaped artifacts under etc/default_skills' do
    described_class.refresh!
    rx = described_class.const_get(:ARTIFACT_RX)
    leftovers = []
    Dir.glob(File.join(PWN::Config.default_skills_dir, '**', '*')).each do |path|
      next unless File.file?(path)
      next unless path.end_with?('.md')

      body = File.read(path)
      leftovers << "#{path}: hermes" if body.match?(/hermes/i)
      leftovers << "#{path}: pem" if body.include?('BEGIN ') && body.include?('PRIVATE KEY')
      leftovers << "#{path}: jwt" if body.match?(/\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/)
      leftovers << "#{path}: token-prefix" if body.match?(/\b(?:sk|rk|ghp|gho|glpat|AKIA|ASIA|ya29|xox[baprs])[-_][A-Za-z0-9\-_]{8,}/)
      next unless path.include?('/default_skills/pwn/')

      leftovers << "#{path}: /home/" if body.match?(%r{/home/[A-Za-z0-9._-]+})
      leftovers << "#{path}: artifact" if body.match?(rx) && !body.include?('[redacted]') && !body.include?('[set in pwn-vault]')
    end
    expect(leftovers).to eq([])
  end
end
