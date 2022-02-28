# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pwn/version'

Gem::Specification.new do |spec|
  spec.required_ruby_version = ">= #{File.read('.ruby-version')}"
  spec.name = 'pwn'
  spec.version = PWN::VERSION
  spec.authors = ['Jacob Hoopes']
  spec.email = ['jake.hoopes@gmail.com']
  spec.summary = 'Automated Security Testing for CI/CD Pipelines & Beyond'
  spec.description = 'https://github.com/0dayinc/pwn/README.md'
  spec.homepage = 'https://github.com/0dayinc/pwn'
  spec.license = 'MIT'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = `git ls-files -z`.split("\x0")
  spec.executables = spec.files.grep(%r{^bin/}) do |f|
    File.basename(f)
  end

  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rdoc'
  spec.add_development_dependency 'rspec'

  File.readlines('./Gemfile').each do |line|
    columns = line.chomp.split
    next unless columns.first == 'gem'

    gem_name = columns[1].delete("'").delete(',')
    gem_version = columns.last.delete("'")
    # spec.add_development_dependency(gem_name, gem_version)
    spec.add_runtime_dependency(gem_name, gem_version)
  end
end
