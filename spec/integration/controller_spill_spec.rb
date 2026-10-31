# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'
require 'fileutils'
require 'json'

RSpec.describe 'controller spill boundary through actual Dispatch' do
  %w[checkpoint transcript].each do |mode|
    it "does not create source files when a worker redirects the parent #{mode} spill path" do
      Dir.mktmpdir('spill-boundary-') do |root|
        source = File.join(root, 'source')
        home = File.join(root, 'home')
        work = File.join(root, 'work')
        FileUtils.mkdir_p([source, home, work])
        fixture = File.expand_path('../support/harness/controller_spill.rb', __dir__)
        stdout, stderr, status = Open3.capture3({ 'HOME' => home }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), fixture, source, work, mode, chdir: work)
        expect(status.success?).to be(true), stderr
        row = JSON.parse(stdout)
        expect(row['changed']).to be(false), row.inspect
        expect(row['dispatch_success']).to be(false)
        expect(row['dispatch_error']).to include('Permission denied')
      end
    end
  end

  %w[ordinary aliased].each do |mode|
    it "denies the #{mode} controller-state inventory while preserving workspace output" do
      Dir.mktmpdir('controller-inventory-') do |root|
        source = File.join(root, 'source')
        home = File.join(root, 'home')
        work = File.join(root, 'work')
        FileUtils.mkdir_p([source, home, work])
        fixture = File.expand_path('../support/harness/controller_state.rb', __dir__)
        stdout, stderr, status = Open3.capture3({ 'HOME' => home }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), fixture, source, work, mode, chdir: work)
        expect(status.success?).to be(true), stderr
        row = JSON.parse(stdout)
        expect(row.dig('result', 'success')).to be(true), row.inspect
        attempts = row.dig('result', 'result')
        expect(attempts.length).to eq(29)
        expect(attempts.values.uniq).to eq(['denied']), attempts.inspect
        expect(row['source_unchanged']).to be(true)
        expect(row['output']).to eq('output remains writable')
      end
    end
  end
end
