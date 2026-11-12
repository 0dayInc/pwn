# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'PWN packaging with unstaged file removals' do
  it 'omits tracked files deleted from the working tree without requiring index changes' do
    Dir.mktmpdir('pwn-package-removal') do |dir|
      FileUtils.cp(File.expand_path('../../pwn.gemspec', __dir__), File.join(dir, 'pwn.gemspec'))
      files = {
        '.ruby-version' => "ruby-#{RUBY_VERSION}\n",
        'Gemfile' => "# frozen_string_literal: true\n",
        'lib/pwn/version.rb' => "module PWN\n  VERSION = '0.0.1'\nend\n",
        'spec/lib/pwn/version_spec.rb' => '# fixture',
        'etc/default_skills/pwn/version/SKILL.md' => '# fixture',
        'lib/pwn/retired_fixture.rb' => '# fixture',
        'spec/lib/pwn/retired_fixture_spec.rb' => '# fixture',
        'etc/default_skills/pwn/retired_fixture/SKILL.md' => '# fixture'
      }
      files.each do |path, body|
        target = File.join(dir, path)
        FileUtils.mkdir_p(File.dirname(target))
        File.write(target, body)
      end
      [%w[git init --quiet], ['git', 'add', '.']].each do |argv|
        output, status = Open3.capture2e(*argv, chdir: dir)
        expect(status.success?).to be(true), output
      end
      removed = files.keys.grep(/retired_fixture/)
      removed.each { |path| File.unlink(File.join(dir, path)) }
      code = "require 'json'; spec = Gem::Specification.load('pwn.gemspec'); abort 'specification failed' unless spec; puts JSON.generate(spec.files)"
      env = { 'RUBYOPT' => nil, 'BUNDLE_GEMFILE' => File.join(dir, 'Gemfile'), 'BUNDLE_LOCKFILE' => File.join(dir, 'Gemfile.lock'), 'BUNDLE_FROZEN' => nil }
      lockfile = Bundler.default_lockfile.to_s
      before = File.binread(lockfile)
      output, error, status = Open3.capture3(env, RbConfig.ruby, '-e', code, chdir: dir)
      expect(File.binread(lockfile)).to eq(before)
      expect(status.success?).to be(true), "#{output}\n#{error}"
      packaged = JSON.parse(output)
      expect(packaged).to include('lib/pwn/version.rb')
      expect(packaged & removed).to be_empty
    end
  end
end
