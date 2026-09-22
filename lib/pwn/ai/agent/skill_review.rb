# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'

module PWN
  module AI
    module Agent
      # Decide whether a completed task should update or create a skill.
      # recommend is the default. auto-safe writes only a small verified addition.
      module SkillReview
        LEDGER = File.join(Dir.home, '.pwn', 'skill_review.jsonl').freeze
        MODES = %w[off recommend auto-safe].freeze

        public_class_method def self.review(opts = {})
          mode = mode_from(mode: opts[:mode])
          request = opts[:request].to_s
          return finish(action: 'skipped', reason: 'mode off', mode: mode, request: request) if mode == 'off'
          return finish(action: 'skipped', reason: 'routine success is not a skill', mode: mode, request: request) unless useful?(opts)

          procedure = procedure_from(procedure: opts[:procedure], evidence: opts[:evidence])
          unless procedure[:ok]
            return finish(action: 'refused', reason: procedure[:reason], mode: mode, request: request) if opts[:procedure]

            return finish(action: 'recommend', reason: 'a structured procedure is required before saving', mode: mode, request: request, verified: false)
          end

          target = locate(name: opts[:name], query: request, procedure: procedure[:text])
          kind = target ? 'update' : 'create'
          verified = verified_execution?(evidence: opts[:evidence])
          proposal = {
            action: 'recommend',
            kind: kind,
            name: target ? target[:name] : opts[:name].to_s,
            mode: mode,
            request: request,
            verified: verified,
            reason: target ? 'closest skill matches the procedure' : 'no existing skill matches',
            path: target && target[:path]
          }
          return finish(proposal.merge(action: 'refused', reason: 'generated module skills are not rewritten')) if generated?(name: proposal[:name], path: proposal[:path])
          return finish(proposal) unless mode == 'auto-safe' && auto_safe?(proposal: proposal, procedure: procedure)

          apply_update(proposal: proposal, procedure: procedure, evidence: opts[:evidence], skills_root: opts[:skills_root])
        end

        public_class_method def self.review_turn(opts = {})
          request = opts[:request].to_s
          correction = defined?(Mistakes) && request.match?(Mistakes::CORRECTION_RX)
          mistake = opts[:mistake]
          if mistake.nil? && defined?(Mistakes) && Mistakes.respond_to?(:top)
            rows = Array(Mistakes.top(limit: 8, unresolved_only: false))
            mistake = rows.find { |row| row.is_a?(Hash) && row[:resolved] == true && row[:count].to_i >= 2 }
            mistake = mistake.merge(source: 'mistakes') if mistake
          end
          review(opts.merge(user_correction: correction == true, mistake: mistake, session_id: opts[:session_id], final: opts[:final]))
        end

        public_class_method def self.note_reuse(opts = {})
          row = {
            name: opts[:name].to_s,
            retrieved: opts[:retrieved] == true,
            reused: opts[:reused] == true,
            regressed: opts[:regressed] == true,
            at: Time.now.utc.iso8601
          }
          append_ledger(row: row)
          row
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Review a completed task and recommend or apply a skill change.
            #{self}.review(
              request: 'required - the completed task text',
              mode: 'optional - off, recommend, or auto-safe; default recommend',
              procedure: 'optional - Hash with when, prerequisites, steps, verification, and failures',
              evidence: 'optional - execution proof with source, fixture_passed, and sessions',
              name: 'optional - skill name to prefer',
              success: 'optional - true alone is a routine success and is skipped',
              user_correction: 'optional - true reviews an explicit operator correction',
              skills_root: 'optional - skills directory for the write'
            )

            # Build a review from the completed turn, including an operator correction or a resolved mistake.
            #{self}.review_turn(
              request: 'required - the completed task text',
              final: 'optional - final answer, not saved as a procedure',
              success: 'optional - true alone does not create a skill',
              session_id: 'optional - session id for the turn',
              mistake: 'optional - resolved mistake Hash with count and source from the mistakes store'
            )

            # Record whether a later task retrieved or reused a reviewed skill.
            #{self}.note_reuse(
              name: 'required - skill name',
              retrieved: 'optional - true when the catalog returned the skill',
              reused: 'optional - true when the procedure was followed',
              regressed: 'optional - true when reuse made the task worse'
            )

            # Print the module authors.
            #{self}.authors
          "
        end

        private_class_method def self.mode_from(opts = {})
          raw = opts[:mode]
          raw = PWN::Env.dig(:ai, :agent, :skill_review) if raw.nil? && defined?(PWN::Env) && PWN::Env.respond_to?(:dig)
          mode = raw.to_s
          mode = 'recommend' if mode.empty? || !MODES.include?(mode)
          mode
        end

        private_class_method def self.useful?(opts = {})
          return true if opts[:user_correction] == true

          return true if opts[:procedure].is_a?(Hash) && opts[:evidence].is_a?(Hash)

          mistake = opts[:mistake]
          mistake.is_a?(Hash) && mistake[:resolved] == true && mistake[:count].to_i >= 2 && mistake[:source].to_s == 'mistakes'
        end

        private_class_method def self.procedure_from(opts = {})
          raw = opts[:procedure]
          return { ok: false, reason: 'procedure is required' } unless raw.is_a?(Hash)

          fields = %i[when prerequisites steps verification failures]
          missing = fields.reject { |key| raw[key].to_s.strip.length >= 8 }
          return { ok: false, reason: "procedure missing #{missing.join(', ')}" } unless missing.empty?

          text = fields.map { |key| "#{key}: #{raw[key].to_s.strip}" }.join("\n")
          return { ok: false, reason: 'secret or target-specific text is not saved' } if sensitive?(text: text)
          return { ok: false, reason: 'raw tool output is not a procedure' } if text.match?(/STDOUT|STDERR/) || text.length > 1200

          { ok: true, text: text }
        end

        private_class_method def self.sensitive?(opts = {})
          opts[:text].to_s.match?(/bearer |password|api_key|BEGIN |token|sk-[A-Za-z0-9]/i) || opts[:text].to_s.match?(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)
        end

        private_class_method def self.verified_execution?(opts = {})
          evidence = opts[:evidence].is_a?(Hash) ? opts[:evidence] : {}
          evidence[:source].to_s == 'execution' && evidence[:fixture_passed] == true && Array(evidence[:sessions]).map(&:to_s).uniq.length >= 3 && evidence[:model_claimed] != true
        end

        private_class_method def self.locate(opts = {})
          return nil unless defined?(PWN::Skills) && PWN::Skills.is_a?(Hash)

          name = opts[:name].to_s
          unless name.empty?
            meta = PWN::Skills[name.to_sym] || PWN::Skills[name]
            return { name: name, path: meta[:path], meta: meta } if meta.is_a?(Hash)
          end

          tokens = "#{opts[:query]} #{opts[:procedure]}".downcase.scan(/[a-z0-9]{4,}/).uniq
          scored = PWN::Skills.map do |key, meta|
            next unless meta.is_a?(Hash)

            hay = "#{key} #{meta[:description]}".downcase
            [key.to_s, meta, tokens.count { |tok| hay.include?(tok) }]
          end.compact
          best = scored.max_by { |_, _, score| score }
          return nil unless best && best[2] >= 2

          { name: best[0], path: best[1][:path], meta: best[1] }
        end

        private_class_method def self.generated?(opts = {})
          opts[:name].to_s.start_with?('pwn/') || opts[:path].to_s.include?('/skills/pwn/')
        end

        private_class_method def self.auto_safe?(opts = {})
          proposal = opts[:proposal] || {}
          procedure = opts[:procedure] || {}
          proposal[:kind] == 'update' && proposal[:verified] == true && procedure[:text].to_s.length <= 400
        end

        private_class_method def self.apply_update(opts = {})
          proposal = opts[:proposal]
          path = proposal[:path].to_s
          return finish(proposal.merge(action: 'refused', reason: 'skill path missing')) unless File.file?(path) && !File.symlink?(path)

          original = File.read(path)
          digest = Digest::SHA256.hexdigest(original)
          backup = "#{path}.#{digest}.bak"
          File.open(backup, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(original) } unless File.exist?(backup)
          signature = (opts[:evidence] || {})[:signature].to_s
          lesson = "#{signature}\n#{opts[:procedure][:text]}"
          written = Learning.update_skill(name: proposal[:name], lesson: lesson, query: proposal[:request], pwn_skills_path: opts[:skills_root])
          current = File.read(path)
          unless current.include?(signature) && !signature.empty?
            File.write(path, original)
            return finish(proposal.merge(action: 'refused', reason: 'readback failed', written: written))
          end

          PWN::Config.load_skills(pwn_skills_path: opts[:skills_root]) if defined?(PWN::Config) && PWN::Config.respond_to?(:load_skills)
          finish(proposal.merge(action: 'applied', backup: backup))
        end

        private_class_method def self.finish(opts = {})
          row = opts.transform_keys(&:to_sym)
          append_ledger(row: row)
          row
        end

        private_class_method def self.append_ledger(opts = {})
          path = LEDGER
          FileUtils.mkdir_p(File.dirname(path))
          File.open(path, 'a') { |file| file.puts(JSON.generate(opts[:row])) }
        rescue StandardError
          nil
        end
      end
    end
  end
end
