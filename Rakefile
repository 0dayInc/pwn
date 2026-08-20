# frozen_string_literal: true

# Bare `rake` often loads the Ruby-shipped rake before this file runs.
# Re-exec under Bundler unless we are already inside bundle exec.
exec('bundle', 'exec', 'rake', *ARGV) unless ENV['BUNDLE_BIN_PATH'] || ENV['RUBYOPT'].to_s.include?('bundler/setup')

require 'bundler/setup'
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
    rdoc.options << '--quiet'
  end
  # RDoc::Task's default :clobber_rdoc uses Rake's verbose FileUtils, which
  # echoes "rm -r rdoc" to STDOUT on every `rake` (via :rerdoc). Replace it
  # with a silent rm_rf so the default task emits only spec/rubocop output.
  Rake::Task[:clobber_rdoc].clear_actions
  task(:clobber_rdoc) { FileUtils.rm_rf('rdoc') }
end

default_tasks = %i[spec rubocop]
default_tasks << :rerdoc if defined?(RDoc::Task)
task default: default_tasks
