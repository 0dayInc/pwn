# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplaySmokeTest < Minitest::Test
  def test_builds_evidence_bundle_and_flags_stale_access
    Dir.mktmpdir('lifecycle-authz-replay-smoke-') do |tmp_dir|
      plan = {
        campaign: {
          id: 'acme-revoke-collaborator',
          target: 'https://example.test',
          change_event: 'remove_collaborator'
        },
        actors: %w[owner revoked_user],
        surfaces: ['repo_settings_page'],
        checkpoints: %w[pre_change post_change_t0],
        expected_denied_after: ['post_change_t0']
      }

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: plan,
        output_dir: tmp_dir,
        run_id: 'smoke-run'
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'pre_change',
        actor: 'owner',
        surface: 'repo_settings_page',
        status: :accessible,
        response: { http_status: 200 }
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'repo_settings_page',
        status: :accessible,
        response: { http_status: 200 },
        notes: 'Still accessible after collaborator removal'
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
        run_obj: run_obj
      )

      assert_equal(1, summary[:totals][:stale_access_findings])
      assert(File.exist?(File.join(tmp_dir, 'smoke-run', 'RUNBOOK.md')))
      assert(File.exist?(File.join(tmp_dir, 'smoke-run', 'coverage_matrix.json')))
      assert(File.exist?(File.join(tmp_dir, 'smoke-run', 'SUMMARY.json')))
      assert(File.exist?(File.join(tmp_dir, 'smoke-run', 'REPORT.md')))
    end
  end
end
