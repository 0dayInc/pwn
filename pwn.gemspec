# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pwn/version'

Gem::Specification.new do |spec|
  # Switch back when RVM has stable 3.1.2 (i.e. not just preview / p20)
  # spec.required_ruby_version = ">= #{File.read('.ruby-version')}"
  required_minor_ruby_version = File.read('.ruby-version').split('.')[0..1].join('.')
  spec.required_ruby_version = ">= #{required_minor_ruby_version}"
  spec.name = 'pwn'
  spec.version = PWN::VERSION
  spec.authors = ['0day Inc.']
  spec.email = ['request.pentest@0dayinc.com']
  spec.summary = 'Automated Security Testing for CI/CD Pipelines & Beyond'
  spec.description = 'https://github.com/0dayinc/pwn/README.md'
  spec.homepage = 'https://github.com/0dayinc/pwn'
  spec.license = 'MIT'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = `git ls-files -z`.split("\x0")
  spec.executables = spec.files.grep(%r{^bin/}) do |f|
    File.basename(f)
  end

  # spec.test_files = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  dev_dependency_arr = %i[
    bundler
    rake
    rdoc
    rspec
  ]

  File.readlines('./Gemfile').each do |line|
    columns = line.chomp.split
    next unless columns.first == 'gem'

    gem_name = columns[1].delete("'").delete(',')
    gem_version = columns.last.delete("'")

    if dev_dependency_arr.include?(gem_name.to_sym)
      spec.add_development_dependency(
        gem_name,
        gem_version
      )
    else
      spec.add_runtime_dependency(
        gem_name,
        gem_version
      )
    end
  end
end
