# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Bounty::LifecycleAuthzReplay do
  it 'builds a normalized evidence bundle and flags stale access' do
    Dir.mktmpdir('lifecycle-authz-replay-spec-') do |tmp_dir|
      run_obj = described_class.start_run(
        plan: {
          campaign: {
            id: 'acme-revoke-collaborator',
            target: 'https://example.test',
            change_event: 'remove_collaborator'
          },
          actors: %w[owner revoked_user],
          surfaces: ['repo_settings_page'],
          checkpoints: %w[pre_change post_change_t0],
          expected_denied_after: ['post_change_t0']
        },
        output_dir: tmp_dir,
        run_id: 'rspec-run'
      )

      described_class.record_observation(
        run_obj: run_obj,
        checkpoint: 'pre_change',
        actor: 'owner',
        surface: 'repo_settings_page',
        status: :accessible,
        response: { http_status: 200 }
      )

      described_class.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'repo_settings_page',
        status: :accessible,
        response: { http_status: 200 },
        notes: 'Still accessible after collaborator removal'
      )

      summary = described_class.finalize_run(run_obj: run_obj)

      expect(summary[:totals][:stale_access_findings]).to eq(1)
      expect(File).to exist(File.join(tmp_dir, 'rspec-run', 'RUNBOOK.md'))
      expect(File).to exist(File.join(tmp_dir, 'rspec-run', 'coverage_matrix.json'))
      expect(File).to exist(File.join(tmp_dir, 'rspec-run', 'SUMMARY.json'))
      expect(File).to exist(File.join(tmp_dir, 'rspec-run', 'REPORT.md'))
    end
  end
end
