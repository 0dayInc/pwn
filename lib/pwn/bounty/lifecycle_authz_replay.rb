# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Bounty
    # YAML-driven helper for capturing lifecycle authz evidence across
    # pre/post state transitions (e.g., collaborator removal, role change,
    # project visibility flips) with report-ready artifacts.
    module LifecycleAuthzReplay
      DEFAULT_CHECKPOINTS = %w[pre_change post_change_t0 post_change_tn].freeze
      STATUS_VALUES = %w[missing accessible denied error unknown].freeze

      # Supported Method Parameters::
      # plan = PWN::Bounty::LifecycleAuthzReplay.load_plan(
      #   yaml_path: '/path/to/lifecycle_authz_replay.yaml'
      # )
      public_class_method def self.load_plan(opts = {})
        yaml_path = opts[:yaml_path]
        raise 'yaml_path is required' if yaml_path.to_s.strip.empty?
        raise "YAML plan does not exist: #{yaml_path}" unless File.exist?(yaml_path)

        raw_plan = YAML.safe_load(File.read(yaml_path), aliases: true) || {}
        normalize_plan(plan: symbolize_obj(raw_plan), plan_id_hint: File.basename(yaml_path, File.extname(yaml_path)))
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
      #   yaml_path: '/path/to/lifecycle_authz_replay.yaml',
      #   output_dir: '/tmp/evidence_bundle'
      # )
      #
      # OR
      # run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
      #   plan: normalized_plan_hash,
      #   output_dir: '/tmp/evidence_bundle'
      # )
      public_class_method def self.start_run(opts = {})
        output_dir = opts[:output_dir].to_s.strip
        output_dir = Dir.pwd if output_dir.empty?

        plan = opts[:plan]
        plan = load_plan(yaml_path: opts[:yaml_path]) if plan.nil?
        plan = normalize_plan(plan: plan) if plan.is_a?(Hash)

        run_id = opts[:run_id].to_s.strip
        run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-#{plan[:campaign][:id]}" if run_id.empty?

        run_root = File.expand_path(File.join(output_dir, run_id))
        artifacts_dir = File.join(run_root, 'artifacts')
        FileUtils.mkdir_p(artifacts_dir)

        run_obj = {
          run_id: run_id,
          run_root: run_root,
          artifacts_dir: artifacts_dir,
          started_at: Time.now.utc.iso8601,
          plan: plan,
          coverage_matrix: build_coverage_matrix(plan: plan),
          observations: []
        }

        write_json(path: File.join(run_root, 'coverage_matrix.json'), obj: run_obj[:coverage_matrix])
        write_yaml(path: File.join(run_root, 'plan.normalized.yaml'), obj: plan)
        write_runbook(run_obj: run_obj)

        run_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Bounty::LifecycleAuthzReplay.record_observation(
      #   run_obj: run_obj,
      #   checkpoint: 'post_change_t0',
      #   actor: 'revoked_user',
      #   surface: 'repo_settings_page',
      #   status: :accessible,
      #   request: { method: 'GET', path: '/org/repo/settings' },
      #   response: { http_status: 200 },
      #   notes: 'Still reachable after collaborator removal',
      #   artifact_paths: ['/tmp/screen.png']
      # )
      public_class_method def self.record_observation(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        checkpoint = normalize_token(opts[:checkpoint])
        actor = normalize_token(opts[:actor])
        surface = normalize_token(opts[:surface])
        status = normalize_token(opts[:status])

        raise 'checkpoint is required' if checkpoint.empty?
        raise 'actor is required' if actor.empty?
        raise 'surface is required' if surface.empty?

        status = 'unknown' if status.empty?
        raise "unsupported status: #{status} (supported: #{STATUS_VALUES.join(', ')})" unless STATUS_VALUES.include?(status)

        coverage_cell = find_coverage_cell(
          coverage_matrix: run_obj[:coverage_matrix],
          checkpoint: checkpoint,
          actor: actor,
          surface: surface
        )

        raise "unknown coverage cell checkpoint=#{checkpoint} actor=#{actor} surface=#{surface}" if coverage_cell.nil?

        evidence = {
          observed_at: Time.now.utc.iso8601,
          checkpoint: checkpoint,
          actor: actor,
          surface: surface,
          status: status,
          request: symbolize_obj(opts[:request] || {}),
          response: symbolize_obj(opts[:response] || {}),
          notes: opts[:notes].to_s,
          artifact_paths: Array(opts[:artifact_paths]).map(&:to_s)
        }

        evidence_path = File.join(
          run_obj[:artifacts_dir],
          checkpoint,
          actor,
          "#{surface}.json"
        )
        write_json(path: evidence_path, obj: evidence)

        coverage_cell[:status] = status
        coverage_cell[:observed_at] = evidence[:observed_at]
        coverage_cell[:evidence_path] = evidence_path

        run_obj[:observations] << evidence.merge(evidence_path: evidence_path)

        write_json(path: File.join(run_obj[:run_root], 'coverage_matrix.json'), obj: run_obj[:coverage_matrix])
        write_coverage_markdown(run_obj: run_obj)

        evidence
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
      #   run_obj: run_obj
      # )
      public_class_method def self.finalize_run(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        coverage_cells = run_obj[:coverage_matrix][:cells]
        missing_cells = coverage_cells.select { |cell| cell[:status] == 'missing' }
        stale_access_findings = find_stale_access_findings(run_obj: run_obj)

        summary = {
          run_id: run_obj[:run_id],
          completed_at: Time.now.utc.iso8601,
          campaign: run_obj[:plan][:campaign],
          totals: {
            checkpoints: run_obj[:plan][:checkpoints].length,
            actors: run_obj[:plan][:actors].length,
            surfaces: run_obj[:plan][:surfaces].length,
            cells: coverage_cells.length,
            captured_cells: coverage_cells.count { |cell| cell[:status] != 'missing' },
            missing_cells: missing_cells.length,
            stale_access_findings: stale_access_findings.length
          },
          stale_access_findings: stale_access_findings,
          missing_cells: missing_cells
        }

        write_json(path: File.join(run_obj[:run_root], 'SUMMARY.json'), obj: summary)
        write_report(run_obj: run_obj, summary: summary)

        summary
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # plan = PWN::Bounty::LifecycleAuthzReplay.normalize_plan(
      #   plan: {
      #     campaign: { id: 'acme-revoke' },
      #     actors: ['owner', 'revoked_user'],
      #     surfaces: ['repo_settings'],
      #     checkpoints: ['pre_change', 'post_change_t0']
      #   }
      # )
      public_class_method def self.normalize_plan(opts = {})
        plan = symbolize_obj(opts[:plan] || {})
        plan_id_hint = normalize_token(opts[:plan_id_hint])

        campaign = symbolize_obj(plan[:campaign] || {})
        campaign_id = normalize_token(campaign[:id])
        campaign_id = normalize_token(campaign[:name]) if campaign_id.empty?
        campaign_id = plan_id_hint if campaign_id.empty?
        campaign_id = 'lifecycle-authz-replay' if campaign_id.empty?

        actors = normalize_named_records(
          list: Array(plan[:actors]),
          fallback: [{ id: 'primary_actor', label: 'Primary Actor' }],
          default_prefix: 'actor'
        )

        surfaces = normalize_named_records(
          list: Array(plan[:surfaces]),
          fallback: [{ id: 'primary_surface', label: 'Primary Surface' }],
          default_prefix: 'surface'
        )

        checkpoints = Array(plan[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) }.reject(&:empty?)
        checkpoints = DEFAULT_CHECKPOINTS if checkpoints.empty?

        expected_denied_after = Array(plan[:expected_denied_after]).map { |checkpoint| normalize_token(checkpoint) }.reject(&:empty?)
        if expected_denied_after.empty?
          expected_denied_after = checkpoints.select { |checkpoint| checkpoint.start_with?('post_change') }
        end

        {
          campaign: {
            id: campaign_id,
            label: campaign[:label].to_s.strip,
            target: campaign[:target].to_s.strip,
            change_event: campaign[:change_event].to_s.strip,
            notes: campaign[:notes].to_s.strip
          },
          actors: actors,
          surfaces: surfaces,
          checkpoints: checkpoints,
          expected_denied_after: expected_denied_after,
          metadata: symbolize_obj(plan[:metadata] || {})
        }
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage Information

      public_class_method def self.help
        <<~HELP
          Usage:
            plan = PWN::Bounty::LifecycleAuthzReplay.load_plan(
              yaml_path: '/path/to/lifecycle_authz_replay.yaml'
            )

            run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
              plan: plan,
              output_dir: '/tmp/evidence-bundles'
            )

            PWN::Bounty::LifecycleAuthzReplay.record_observation(
              run_obj: run_obj,
              checkpoint: 'post_change_t0',
              actor: 'revoked_user',
              surface: 'repo_settings_page',
              status: :accessible,
              request: { method: 'GET', path: '/org/repo/settings' },
              response: { http_status: 200 },
              notes: 'Still reachable after remove action',
              artifact_paths: ['/tmp/screenshot.png']
            )

            summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
              run_obj: run_obj
            )
        HELP
      end

      private_class_method def self.find_stale_access_findings(opts = {})
        run_obj = opts[:run_obj]
        expected_denied_after = run_obj[:plan][:expected_denied_after]

        run_obj[:coverage_matrix][:cells].select do |cell|
          expected_denied_after.include?(cell[:checkpoint]) && cell[:status] == 'accessible'
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.find_coverage_cell(opts = {})
        coverage_matrix = opts[:coverage_matrix]
        checkpoint = opts[:checkpoint]
        actor = opts[:actor]
        surface = opts[:surface]

        coverage_matrix[:cells].find do |cell|
          cell[:checkpoint] == checkpoint && cell[:actor] == actor && cell[:surface] == surface
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.build_coverage_matrix(opts = {})
        plan = opts[:plan]

        cells = []
        plan[:checkpoints].each do |checkpoint|
          plan[:actors].each do |actor|
            plan[:surfaces].each do |surface|
              cells << {
                checkpoint: checkpoint,
                actor: actor[:id],
                surface: surface[:id],
                status: 'missing',
                observed_at: nil,
                evidence_path: nil
              }
            end
          end
        end

        {
          generated_at: Time.now.utc.iso8601,
          status_values: STATUS_VALUES,
          cells: cells
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_runbook(opts = {})
        run_obj = opts[:run_obj]
        plan = run_obj[:plan]
        runbook_path = File.join(run_obj[:run_root], 'RUNBOOK.md')

        runbook_lines = []
        runbook_lines << "# Lifecycle Authz Replay Runbook"
        runbook_lines <<
          "Run ID: `#{run_obj[:run_id]}`  " \
          "Campaign: `#{plan[:campaign][:id]}`  " \
          "Target: `#{plan[:campaign][:target]}`"
        runbook_lines << ''
        runbook_lines << '## Checkpoint capture checklist'

        plan[:checkpoints].each do |checkpoint|
          expected_status = plan[:expected_denied_after].include?(checkpoint) ? 'denied' : 'accessible'
          runbook_lines << ''
          runbook_lines << "### #{checkpoint} (expected status: #{expected_status})"

          plan[:actors].each do |actor|
            plan[:surfaces].each do |surface|
              runbook_lines << "- [ ] actor=`#{actor[:id]}` surface=`#{surface[:id]}`"
            end
          end
        end

        runbook_lines << ''
        runbook_lines << '## Artifact locations'
        runbook_lines << '- coverage matrix: `coverage_matrix.json` + `coverage_matrix.md`'
        runbook_lines << '- evidence: `artifacts/<checkpoint>/<actor>/<surface>.json`'
        runbook_lines << '- report output: `SUMMARY.json` + `REPORT.md`'

        File.write(runbook_path, runbook_lines.join("\n"))

        write_coverage_markdown(run_obj: run_obj)
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_coverage_markdown(opts = {})
        run_obj = opts[:run_obj]
        coverage_path = File.join(run_obj[:run_root], 'coverage_matrix.md')

        lines = []
        lines << '# Coverage Matrix'
        lines << ''
        lines << '| Checkpoint | Actor | Surface | Status | Evidence |'
        lines << '| --- | --- | --- | --- | --- |'

        run_obj[:coverage_matrix][:cells].each do |cell|
          evidence = cell[:evidence_path].to_s
          evidence = File.basename(evidence) unless evidence.empty?
          lines << "| #{cell[:checkpoint]} | #{cell[:actor]} | #{cell[:surface]} | #{cell[:status]} | #{evidence} |"
        end

        File.write(coverage_path, lines.join("\n"))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_report(opts = {})
        run_obj = opts[:run_obj]
        summary = opts[:summary]

        lines = []
        lines << '# Lifecycle Authz Replay Report'
        lines << ''
        lines << "- Run ID: `#{summary[:run_id]}`"
        lines << "- Campaign: `#{summary[:campaign][:id]}`"
        lines << "- Completed At (UTC): `#{summary[:completed_at]}`"
        lines << "- Captured Cells: `#{summary[:totals][:captured_cells]}` / `#{summary[:totals][:cells]}`"
        lines << "- Missing Cells: `#{summary[:totals][:missing_cells]}`"
        lines << ''

        lines << '## Stale Access Findings'
        if summary[:stale_access_findings].empty?
          lines << '- No stale-access cells confirmed in expected-denied checkpoints.'
        else
          summary[:stale_access_findings].each do |finding|
            lines << "- checkpoint=`#{finding[:checkpoint]}` actor=`#{finding[:actor]}` surface=`#{finding[:surface]}` evidence=`#{finding[:evidence_path]}`"
          end
        end

        lines << ''
        lines << '## Missing Coverage Cells'
        if summary[:missing_cells].empty?
          lines << '- Coverage complete for planned cells.'
        else
          summary[:missing_cells].each do |cell|
            lines << "- checkpoint=`#{cell[:checkpoint]}` actor=`#{cell[:actor]}` surface=`#{cell[:surface]}`"
          end
        end

        File.write(File.join(run_obj[:run_root], 'REPORT.md'), lines.join("\n"))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_named_records(opts = {})
        list = opts[:list]
        fallback = opts[:fallback]
        default_prefix = normalize_token(opts[:default_prefix])

        list = fallback if list.empty?

        normalized = []
        list.each_with_index do |entry, index|
          item = entry
          item = { id: entry.to_s, label: entry.to_s } unless item.is_a?(Hash)
          item = symbolize_obj(item)

          id = normalize_token(item[:id])
          id = normalize_token(item[:name]) if id.empty?
          id = "#{default_prefix}_#{index + 1}" if id.empty?

          label = item[:label].to_s.strip
          label = item[:name].to_s.strip if label.empty?
          label = id if label.empty?

          normalized << {
            id: id,
            label: label,
            metadata: symbolize_obj(item[:metadata] || {})
          }
        end

        normalized
      rescue StandardError => e
        raise e
      end

      private_class_method def self.symbolize_obj(obj)
        case obj
        when Array
          obj.map { |entry| symbolize_obj(entry) }
        when Hash
          obj.each_with_object({}) do |(key, value), accum|
            symbolized_key = key.respond_to?(:to_sym) ? key.to_sym : key
            accum[symbolized_key] = symbolize_obj(value)
          end
        else
          obj
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_token(token)
        token.to_s.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_json(opts = {})
        path = opts[:path]
        obj = opts[:obj]
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, JSON.pretty_generate(obj))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_yaml(opts = {})
        path = opts[:path]
        obj = opts[:obj]
        FileUtils.mkdir_p(File.dirname(path))
        yaml_obj = YAML.dump(obj).gsub(/^\s*:(\w+):/, '\\1:')
        File.write(path, yaml_obj)
      rescue StandardError => e
        raise e
      end
    end
  end
end
