# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'
require 'open3'

describe PWN::ModuleSkills do
  it 'saves legacy generated edits and merges without discarding unrelated edits' do
    script = File.read(File.expand_path('../../../build_gem.sh', __dir__))
    recovery = script.split('generated_skills=()', 2).last.split('git checkout master', 2).first
    Dir.mktmpdir('pwn_upgrade') do |dir|
      git = lambda do |*args|
        out, status = Open3.capture2e('git', *args, chdir: dir)
        expect(status.success?).to be(true), out
        out
      end
      git.call('init', '-b', 'master')
      git.call('config', 'user.email', 'test@example.invalid')
      git.call('config', 'user.name', 'Upgrade Test')
      skill = 'etc/default_skills/pwn/json_text/SKILL.md'
      path = File.join(dir, skill)
      FileUtils.mkdir_p(File.dirname(path))
      original = "---\ngenerated: true\n---\noriginal\n"
      File.write(path, original)
      File.write(File.join(dir, 'notes'), 'original')
      git.call('add', '.')
      git.call('commit', '-m', 'base')
      git.call('checkout', '-b', 'incoming')
      File.write(path, "#{original}upstream\n")
      git.call('commit', '-am', 'update')
      git.call('checkout', 'master')
      File.write(path, "#{original}local regeneration\n")
      File.write(File.join(dir, 'notes'), 'keep my edit')
      _, blocked = Open3.capture2e('git', 'merge', '--ff-only', 'incoming', chdir: dir)
      expect(blocked.success?).to be(false)
      out, status = Open3.capture2e('bash', '-ec', "generated_skills=()#{recovery}", chdir: dir)
      expect(status.success?).to be(true), out
      git.call('merge', '--ff-only', 'incoming')
      expect(File.read(path)).to eq("#{original}upstream\n")
      expect(File.read(File.join(dir, 'notes'))).to eq('keep my edit')
      expect(git.call('show', "stash@{0}:#{skill}")).to include('local regeneration')
    end
  end

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

  it 'refreshes a temp skill tree and does not rewrite the checkout' do
    checkout = File.join(PWN::ModuleSkills::GEM_SKILLS, 'json_text', 'SKILL.md')
    before = File.read(checkout)
    Dir.mktmpdir('pwn_mod_refresh') do |dir|
      report = described_class.refresh!(dest: dir)
      expect(report[:modules]).to be > 50
      tb = File.join(dir, 'pwn', 'plugins', 'transparent_browser', 'SKILL.md')
      expect(File.file?(tb)).to eq(true), tb
      expect(File).not_to exist(File.join(dir, 'pwn', 'plugins', 'transparent_browser.md'))
      body = File.read(tb)
      expect(body).to include('PWN::Plugins::TransparentBrowser')
      expect(body).to include('open')
      expect(body).not_to match(/hermes/i)

      pw = File.join(dir, 'pwn', 'sast', 'password', 'SKILL.md')
      expect(File.file?(pw)).to eq(true), pw
      expect(File.file?(File.join(dir, 'pwn', 'sast', 'password', 'references', 'security.md'))).to eq(true)

      described_class.enumerate.each do |rec|
        path = File.join(dir, described_class.relpath(source: rec[:source], const: rec[:const]))
        expect(File.file?(path)).to eq(true), path
        expect(File.read(path)).to include(rec[:const])
        expect(File.read(path)).not_to match(/hermes/i)
      end
      drift = described_class.drift(dest: dir)
      expect(drift[:missing]).to eq([])
      expect(drift[:stale]).to eq([])
      expect(drift[:orphans]).to eq([])
    end
    expect(File.read(checkout)).to eq(before)

    gw = File.join(PWN::ModuleSkills::GEM_SKILLS, 'plugins', 'google_workspace', 'SKILL.md')
    expect(File.read(gw)).to include('preserve: true')
    expect(File.read(gw)).to include('gmail_search')
    expect(File.read(gw)).to include('daily-brief.md')
    expect(File).not_to exist(File.join(PWN::Config.default_skills_dir, 'productivity', 'google-workspace', 'SKILL.md'))
  end

  it 'does not rewrite the checkout before spec' do
    rake = File.read(File.expand_path('../../../Rakefile', __dir__))
    expect(rake).to match(/task :module_skills do/)
    expect(rake).to match(/ModuleSkills\.refresh!/)
    expect(rake).not_to match(/Task\[:spec\]\.enhance\(\[:module_skills\]\)/)
    expect(rake).not_to match(/module_skills_drift/)
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
