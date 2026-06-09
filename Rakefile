# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rdoc/task'
require 'rubocop/rake_task'

RSpec::Core::RakeTask.new(:spec)

RuboCop::RakeTask.new do |rubocop|
  config_file = '.rubocop.yml'
  rubocop.options = ['-E', '-S', '-c', config_file]
end

if defined?(RDoc::Task)
  RDoc::Task.new do |rdoc|
    rdoc.rdoc_files.include('lib/**/*.rb')
    rdoc.rdoc_dir = 'rdoc'
  end
end

default_tasks = %i[spec rubocop]
default_tasks << :rdoc if defined?(RDoc::Task)
task default: default_tasks
