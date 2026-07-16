# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'pwn/version'

Gem::Specification.new do |spec|
  ruby_version = ">= #{File.read('.ruby-version').split('-').last.chomp}".freeze
  # spec.required_ruby_version = ruby_version
  spec.required_ruby_version = '>= 3.3'
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

  # `-c safe.directory='*'` — container CI (actions/checkout in a `container:` job)
  # leaves the checkout owned by a different UID than the step's shell, so a
  # bare `git ls-files` fails with "detected dubious ownership" and this gem
  # would silently build with ZERO files. Force-trust the cwd for this one
  # read-only invocation and fail LOUD if it's still empty.
  spec.files = `git -c safe.directory='*' ls-files -z 2>/dev/null`.split("\x00")
  raise "pwn.gemspec: git ls-files returned no files - not a git checkout, or git safe.directory refused '#{__dir__}'" if spec.files.empty?

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

  # Native-extension gems (and gems that hard-depend on them) whose OS
  # headers are provisioned *after* install by `pwn setup` / PWN::Setup.
  # They are declared as *development* dependencies so that
  #     gem install pwn
  # succeeds on a bare host (documentation/Installation.md's two-step
  # promise) and `pwn setup --profile <x>` then installs the OS packages
  # + `gem install`s these on demand. Keep in sync with
  # PWN::Setup::NATIVE_GEMS (lib/pwn/setup.rb).
  setup_managed_arr = %w[
    curses
    eventmachine
    faye-websocket
    gruff
    libusb
    meshtastic
    packetfu
    packetgen
    pg
    rmagick
    rtesseract
    ruby-audio
    sqlite3
    thin
    waveform
  ]

  File.readlines('./Gemfile').each do |line|
    # Robust parser: extract name and version using regex to handle quotes, operators (>=, <), and avoid empty/invalid versions.
    # Anchor with ^\\s* to only match active (non-commented) gem declarations at start of line.
    match = line.match(/^\s*gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/)
    next unless match

    gem_name = match[1]
    gem_version = match[2]

    # Good for debugging issues in Gemfile
    # puts "pwn.gemspec: Adding dependency: #{gem_name} #{gem_version}"

    if dev_dependency_arr.include?(gem_name.to_sym) || setup_managed_arr.include?(gem_name)
      # setup_managed_arr gems are installed post-hoc by `pwn setup` (PWN::Setup.deps)
      # once the matching OS headers are present — NOT hard runtime dependencies.
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
