# frozen_string_literal: true

require 'digest'
require 'time'

module PWN
  module AI
    module Agent
      # Conservative, deterministic SOP hygiene. Content proposals are pure;
      # writes require an explicit path and optimistic-concurrency digest.
      module SkillConsolidation
        STAMP = /^<!-- pwn-skill-version: [a-f0-9]+ updated: [^>]+ -->\n?/

        public_class_method def self.consolidate(opts = {})
          original = opts.fetch(:content).to_s
          content = original.sub(STAMP, '')
          evidence = (opts[:evidence] || {}).transform_keys(&:to_s)
          now = opts[:now] || Time.now.utc
          stale_days = Float(opts[:stale_days] || 90)
          promoted = []
          review = []
          promoted_lines = []
          review_lines = []
          feedback = content.scan(/^\s*- \[([^\]]+)\]\s+(.+)$/).group_by(&:first)
          sop_lines = content.split(/^\#{1,3}\s+RL feedback\s*$/i).first.to_s.lines.map { |line| line.strip.delete_prefix('- ').downcase }
          seen = {}
          deduplicated = 0
          in_feedback = false
          in_verified = false
          lines = content.lines.filter_map do |line|
            if line.match?(/^\#{1,3}\s/)
              in_feedback = line.strip.match?(/^\#{1,3}\s+RL feedback$/i)
              in_verified = line.strip.match?(/^\#{1,3}\s+Verified procedures$/i)
            end
            match = (in_feedback || in_verified) && line.match(/^\s*- \[([^\]]+)\]\s+(.+)$/)
            next line unless match

            key = match[2].strip.sub(/\A\[\d{4}-\d{2}-\d{2}\]\s*/, '').gsub(/\s+/, ' ')
            id = match[1]
            proof = (evidence[id] || {}).transform_keys(&:to_sym)
            verified_at = begin
              DateTime.iso8601((proof[:last_verified] || match[2][/\A\[(\d{4}-\d{2}-\d{2})\]/, 1]).to_s).to_time
            rescue ArgumentError
              nil
            end
            reason = if feedback[id].map(&:last).uniq.length > 1
                       'conflicting feedback'
                     elsif (key.match?(/\A(?:never|do not) /i) && sop_lines.include?(key.sub(/\A(?:never|do not) /i, '').downcase)) || sop_lines.include?("never #{key.downcase}") || sop_lines.include?("do not #{key.downcase}")
                       'contradicts SOP'
                     elsif proof[:regressed] || proof[:contradicted]
                       'contradicted verification'
                     elsif verified_at && (now - verified_at) > stale_days * 86_400
                       'stale verification'
                     end
            if reason
              review << { id: id, reason: reason, text: match[2] }
              review_lines << "- [#{id}] (#{reason}) #{match[2]}\n"
              next
            end
            if seen[key]
              deduplicated += 1
              next
            end
            seen[key] = true
            if !in_verified && proof[:resolved] == true && verified_at && verified_at <= now && Array(proof[:verified_sessions]).map(&:to_s).reject(&:empty?).uniq.length >= 3
              promoted << id
              promoted_lines << line
              next
            end
            line
          end
          content = lines.join
          content = "#{content.rstrip}\n\n## Verified procedures\n#{promoted_lines.join}" unless promoted_lines.empty?
          content = "#{content.rstrip}\n\n## Feedback pending review (not active SOP)\n#{review_lines.uniq.join}" unless review_lines.empty?
          version = Digest::SHA256.hexdigest(content)[0, 12]
          previous = original[STAMP].to_s
          stamp = previous.include?("version: #{version} ") ? previous : "<!-- pwn-skill-version: #{version} updated: #{(opts[:now] || Time.now.utc).iso8601} -->\n"
          # Keep YAML frontmatter as the first bytes for existing loaders.
          content = if content.start_with?("---\n")
                      content.sub(/\A---\n.*?\n---\n/m) { |fm| "#{fm}#{stamp}" }
                    else
                      "#{stamp}#{content}"
                    end
          { content: content, version: version, changed: content != original, deduplicated: deduplicated, promoted: promoted, review: review }
        end

        public_class_method def self.consolidate_file(opts = {})
          return PWN::Backups.transaction { consolidate_file(opts) } if opts[:dry_run] == false && !PWN::Backups.active?

          path = File.expand_path(opts.fetch(:path))
          raise ArgumentError, 'symlink skills are not writable consolidation targets' if File.symlink?(path)

          original = File.read(path)
          digest = Digest::SHA256.hexdigest(original)
          result = consolidate(opts.merge(content: original)).merge(path: path, source_sha256: digest, written: false)
          return result unless opts[:dry_run] == false
          raise ArgumentError, 'confirm:true and matching expected_sha256 required' unless opts[:confirm] == true && opts[:expected_sha256] == digest
          return result unless result[:changed]

          File.open("#{path}.consolidation.lock", File::RDWR | File::CREAT, 0o600) do |lock|
            lock.flock(File::LOCK_EX)
            raise ArgumentError, 'skill changed during consolidation' unless File.read(path) == original && !File.symlink?(path)

            backup = PWN::Backups.capture(path: path, label: 'skill-consolidation')
            tmp = "#{path}.#{Process.pid}.tmp"
            File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, File.stat(path).mode & 0o777) do |file|
              file.write(result[:content])
              file.flush
              file.fsync
            end
            File.rename(tmp, path)
            raise IOError, 'consolidation readback mismatch' unless File.read(path) == result[:content]

            result.merge(written: true, backup_path: backup)
          ensure
            File.delete(tmp) if tmp && File.exist?(tmp)
          end
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Propose deterministic RL feedback hygiene without writing files.
            #{self}.consolidate(
              content: 'required - skill markdown including frontmatter',
              evidence: 'optional - id keyed resolved/verified_sessions/last_verified/regressed proofs',
              now: 'optional - current UTC time',
              stale_days: 'optional - verification freshness horizon, default 90'
            )

            # Preview or explicitly apply a content-addressed consolidation with backup.
            #{self}.consolidate_file(
              path: 'required - exact skill file path',
              dry_run: 'optional - default true; false enables writes',
              confirm: 'optional - must be true for a write',
              expected_sha256: 'optional - preview source_sha256, required for a write',
              evidence: 'optional - same proof map as consolidate',
              now: 'optional - current UTC time',
              stale_days: 'optional - verification freshness horizon'
            )

            # Print the module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
