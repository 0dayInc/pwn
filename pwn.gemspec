# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'pwn/version'

Gem::Specification.new do |spec|
  ruby_version = ">= #{File.read('.ruby-version').split('-').last.chomp}".freeze
  # spec.required_ruby_version = ruby_version
  spec.required_ruby_version = '>= 4.0.0'
  spec.name = 'pwn'
  spec.version = PWN::VERSION
  spec.authors = ['0day Inc.']
  spec.email = ['request.pentest@0dayinc.com']
  spec.summary = 'Automated Security Testing for CI/CD Pipelines & Beyond'
  spec.description = 'https://github.com/0dayinc/pwn/README.md'
  spec.homepage = 'https://github.com/0dayinc/pwn'
  spec.license = 'MIT'
  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['funding_uri'] = 'https://github.com/sponsors/0dayInc'

  spec.files = `git ls-files -z`.split("\x00")
  spec.executables = spec.files.grep(%r{^bin/}) do |f|
    File.basename(f)
  end

  spec_tests = spec.files.grep(%r{^spec/})
  pwn_modules = spec.files.grep(%r{^lib/})

  missing_rspec = false
  pwn_modules.each do |mod_path|
    spec_dirname_for_mod = "spec/#{File.dirname(mod_path)}"
    spec_test_for_mod = "#{File.basename(mod_path).split('.').first}_spec.rb"
    spec_path_for_mod = "#{spec_dirname_for_mod}/#{spec_test_for_mod}"
    next unless spec_tests.grep(/#{spec_path_for_mod}/).empty?

    missing_rspec = true
    error_msg = "ERROR: No RSpec: #{spec_path_for_mod} for PWN Module: #{mod_path}"
    # Display error message in red (octal encoded ansi sequence)
    puts "\001\e[1m\002\001\e[31m\002#{error_msg}\001\e[0m\002"
  end

  raise if missing_rspec

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

    # Good for debugging issues in Gemfile
    # puts "pwn.gemspec: Adding dependency: #{gem_name} #{gem_version}"

    if dev_dependency_arr.include?(gem_name.to_sym)
      spec.add_development_dependency(
        gem_name,
        gem_version
      )
    else
      spec.add_dependency(
        gem_name,
        gem_version
      )
    end
  end
end
