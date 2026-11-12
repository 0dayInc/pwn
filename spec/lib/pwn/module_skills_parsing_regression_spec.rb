# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::ModuleSkills source parsing' do
  include_context 'pwn tmp sandbox'

  it 'preserves predicate, bang and setter suffixes in generated public method names' do
    lib = File.join(@tmp, 'lib')
    FileUtils.mkdir_p(File.join(lib, 'pwn'))
    File.write(File.join(lib, 'pwn', 'fixture.rb'), <<~RUBY)
      module PWN
        module Fixture
          public_class_method def self.ready?(opts = {}); opts[:ready]; end
          public_class_method def self.refresh!(opts = {}); opts[:refresh]; end
          public_class_method def self.value=(value); @value = value; end
        end
      end
    RUBY
    record = PWN::ModuleSkills.enumerate(lib_root: lib).first
    expect(record[:methods]).to contain_exactly('ready?', 'refresh!', 'value=')
  end

  it 'refuses to prune existing skills when the source tree has no modules' do
    dest = File.join(@tmp, 'skills')
    skill = File.join(dest, 'pwn', 'fixture', 'SKILL.md')
    FileUtils.mkdir_p(File.dirname(skill))
    File.write(skill, 'keep existing generated skill')
    expect do
      PWN::ModuleSkills.refresh!(lib_root: File.join(@tmp, 'missing-lib'), dest: dest)
    end.to raise_error(ArgumentError, /no PWN modules/i)
    expect(File.read(skill)).to eq('keep existing generated skill')
  end
end
