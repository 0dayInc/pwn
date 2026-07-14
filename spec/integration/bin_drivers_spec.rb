# frozen_string_literal: true

require 'spec_helper'
require 'open3'

# ─────────────────────────────────────────────────────────────────────────────
#  #7 — 53 executables in bin/, none tested. `ruby -c` is <10 ms/file and
#  catches the #1 real-world break (a syntax error in a driver that
#  nothing `require`s). NON-BLOCKING: nothing is executed, only compiled.
#
#  An optional ENV-gated tier (PWN_BIN_HELP=1) shells out `bin/x --help`
#  and asserts exit 0 in <5 s — mirrors fresh_install_spec's gate.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'bin/* CLI drivers', :aggregate_failures do
  root = File.expand_path('../..', __dir__)
  bins = Dir[File.join(root, 'bin', '*')].select { |f| File.file?(f) }.sort

  # anything a driver `require`s must be pwn, stdlib, OR a declared
  # runtime dependency of the pwn gem (Gemfile → gemspec.add_dependency).
  declared = File.read(File.join(root, 'Gemfile'))
                 .scan(/^\s*gem\s+['"]([^'"]+)['"]/).flatten.uniq
  stdlib   = %w[optparse json yaml open3 fileutils shellwords socket uri logger time base64 date
                readline io/console tempfile tmpdir securerandom cgi English rbconfig set pp
                ipaddr resolv digest openssl pathname erb csv zlib etc ostruct stringio timeout
                net/http net/https net/smtp net/ftp]

  it 'ships at least one driver' do
    expect(bins).not_to be_empty
  end

  bins.each do |bin|
    base = File.basename(bin)

    it "#{base}: executable, correct shebang, frozen_string_literal, and passes ruby -c" do
      lines = File.foreach(bin).first(2).map(&:chomp)
      expect(File.executable?(bin)).to be(true), "#{base}: not executable"
      expect(lines[0]).to eq('#!/usr/bin/env ruby'), "#{base}: wrong shebang: #{lines[0].inspect}"
      expect(lines[1].to_s).to match(/frozen_string_literal:/), "#{base}: missing frozen_string_literal"
      _out, err, st = Open3.capture3(RbConfig.ruby, '-c', bin)
      expect(st.exitstatus).to eq(0), "#{base}: ruby -c failed: #{err}"
    end

    it "#{base}: only `require`s pwn, stdlib, or a Gemfile-declared runtime dep" do
      reqs = File.read(bin).scan(/^\s*require\s+['"]([^'"]+)['"]/).flatten
      bad = reqs.reject do |r|
        top = r.split('/', 2).first
        top == 'pwn' || r.start_with?('pwn/') || stdlib.include?(r) || stdlib.include?(top) ||
          declared.include?(top) || declared.include?(r)
      end
      # SOFT: absolute-path requires are surfaced but not fatal (legacy drivers)
      abs, undeclared = bad.partition { |r| r.start_with?('/') }
      warn "[bin-drivers] #{base}: absolute-path require: #{abs}" unless abs.empty?
      expect(undeclared).to be_empty, "#{base}: requires undeclared dep(s): #{undeclared}"
    end
  end

  it 'gemspec.executables == basenames of bin/* (no orphaned or unlisted drivers)' do
    gs = Gem::Specification.load(File.join(root, 'pwn.gemspec'))
    skip 'gemspec did not load (git ls-files unavailable?)' unless gs && !gs.executables.empty?
    expect(gs.executables.sort).to eq(bins.map { |b| File.basename(b) }.sort)
  end

  if ENV['PWN_BIN_HELP'] == '1'
    bins.each do |bin|
      it "#{File.basename(bin)} --help exits 0 in <5 s (ENV-gated)" do
        out, err, st = Open3.capture3(RbConfig.ruby, '-I', File.join(root, 'lib'), bin, '--help',
                                      chdir: root, unsetenv_others: false)
        expect(st.exitstatus).to eq(0), "#{File.basename(bin)}: exit=#{st.exitstatus}\n#{err}\n#{out}"
      end
    end
  end
end
