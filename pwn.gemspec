# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'pwn/version'

Gem::Specification.new do |spec|
  spec.required_ruby_version = ">= #{File.read('.ruby-version').split('-').last.chomp}"
  spec.name = 'pwn'
  spec.version = PWN::VERSION
  spec.authors = ['0day Inc.']
  spec.email = ['request.pentest@0dayinc.com']
  spec.summary = 'Automated Security Testing for CI/CD Pipelines & Beyond'
  spec.description = 'https://github.com/0dayinc/pwn/README.md'
  spec.homepage = 'https://github.com/0dayinc/pwn'
  spec.license = 'MIT'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = `git ls-files -z`.split("\x00")
  spec.executables = spec.files.grep(%r{^bin/}) do |f|
    File.basename(f)
  end

  spec_tests = spec.files.grep(%r{^spec/})
  pwn_modules = spec.files.grep(%r{^lib/})

  missing_rspec = false
  pwn_modules.each do |pwn_path|
    spec_test_for_mod = "#{File.basename(pwn_path).split('.').first}_spec.rb"
    next unless spec_tests.grep(/#{spec_test_for_mod}/).empty?

    missing_rspec = true
    pwn_mod_dir = File.dirname(pwn_path)
    spec_test = "/spec/#{pwn_mod_dir}/#{spec_test_for_mod}"
    error_msg = "ERROR: RSpec: #{spec_test} missing for PWN Module: #{pwn_path}"
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
