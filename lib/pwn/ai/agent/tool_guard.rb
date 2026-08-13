# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # Shared pre-dispatch guards for the two high-volume runtime tools
      # (shell / pwn_eval). Rejects placeholder payloads, aliases wrong
      # schema keys, shares the recon authorization gate, and names the
      # shell that will actually run the command.
      module ToolGuard
        ALIASES = {
          'command' => %w[value cmd input],
          'code' => %w[value source ruby input],
          'query' => %w[value q text]
        }.freeze

        # Token-level junk the model keeps emitting instead of a real command.
        PLACEHOLDER_RX = /
          \A\s*(?:\.{3}|…|\{\s*\.{3}\s*\}|\{\s*…\s*\}|<\.{3}>)\s*\z
          |(?:^|[\s;|&])(?:\.{3}|…|\{\s*\.{3}\s*\}|\{\s*…\s*\})(?:$|[\s;|&])
        /x

        # Conservative bash-only constructs. POSIX `$(())` is allowed.
        BASHISM_RX = /
          \bPIPESTATUS\b
          |\[\[(?:\s|\z)
          |(?:^|[\s;|&])source\s+\S
          |<\([^)]
          |&>
        /x

        RECON_RX = %r{
          (?:^|[;&|\s])(?:sudo\s+)?hping3?(?:\s|$).*(?:-1|--icmp|--flood|/[0-9]{1,2}|seq\s+|for\s+)
          |(?:^|[;&|\s])(?:sudo\s+)?nmap\b[^\n]*(?:-sn|-sP|-PE|-PP|-PM)[^\n]*(?:/[0-9]{1,2}|\d+\.\d+\.\d+\.\d+)
          |(?:^|[;&|\s])(?:sudo\s+)?masscan\b
          |(?:^|[;&|\s])(?:sudo\s+)?nping\b
          |(?:^|[;&|\s])(?:sudo\s+)?fping\b[^\n]*/
          |for\s+\w+\s+in\s+\$?\(?seq[^)]*\)?[^;]*;\s*do\s[^;]*(?:hping|ping\s+-c|nmap)
          |PWN::Plugins::NmapIt
          |\bNmapIt\.(?:scan|new|help)
        }ix

        public_class_method def self.present?(opts = {})
          value = opts.is_a?(Hash) ? opts[:value] : opts
          !value.nil? && !value.to_s.strip.empty?
        end

        public_class_method def self.placeholder?(opts = {})
          PLACEHOLDER_RX.match?(opts[:text].to_s)
        rescue StandardError
          false
        end

        public_class_method def self.bashism?(opts = {})
          BASHISM_RX.match?(opts[:text].to_s)
        rescue StandardError
          false
        end

        public_class_method def self.recon_text?(opts = {})
          RECON_RX.match?(opts[:text].to_s)
        rescue StandardError
          false
        end

        public_class_method def self.recon_authorized?(opts = {})
          return true if Thread.current[:pwn_recon_authorized] == true
          return true if defined?(Loop) && Loop.respond_to?(:recon_authorized?) &&
                         Loop.recon_authorized?(request: opts[:request].to_s)

          v = (PWN::Env.dig(:ai, :agent, :recon_authorized) if defined?(PWN::Env))
          v == true || v.to_s.match?(/\A(1|true|yes|on)\z/i)
        rescue StandardError
          false
        end

        public_class_method def self.shell_bash?
          v = (PWN::Env.dig(:ai, :agent, :shell_bash) if defined?(PWN::Env))
          v == true || v.to_s.match?(/\A(1|true|yes|on)\z/i)
        rescue StandardError
          false
        end

        public_class_method def self.shell_name
          shell_bash? ? 'bash -lc' : '/bin/sh'
        end

        # Coerce common wrong keys onto the first required schema field.
        # Returns the args hash; sets :__schema_error when still missing.
        public_class_method def self.coerce_args(opts = {})
          args = (opts[:args] || {}).dup
          args = args.each_with_object({}) { |(k, v), m| m[k.to_sym] = v } unless args.empty?
          req = Array(opts[:required]).map(&:to_s)
          req.each do |key|
            next if present?(value: args[key.to_sym])

            hit = Array(ALIASES[key]).find { |a| present?(value: args[a.to_sym]) }
            args[key.to_sym] = args[hit.to_sym] if hit
          end
          missing = req.reject { |k| present?(value: args[k.to_sym]) }
          unless missing.empty?
            args[:__schema_error] = "missing required #{missing.join(', ')}"
            args[:__expected] = req
            args[:__schema_hint] =
              "Expected keys: #{req.join(', ')}. " \
              'Do not send value/placeholder/ellipsis. ' \
              'Example: shell(command="uname -r") or pwn_eval(code="1+1").'
          end
          args
        rescue StandardError
          opts[:args] || {}
        end

        public_class_method def self.invalid_payload(opts = {})
          hint = opts[:hint].to_s
          {
            stdout: '',
            stderr: hint,
            exit: 2,
            error: 'invalid_payload',
            hint: hint,
            shell: opts[:shell] || shell_name
          }
        end

        public_class_method def self.recon_blocked(opts = {})
          refused = opts[:text].to_s[0, 200]
          msg = '[pwn-ai/guard] blocked unauthorized recon/sweep. ' \
                'Need explicit in-scope authorization on the user request or ' \
                'PWN::Env[:ai][:agent][:recon_authorized]=true. ' \
                "Refused: #{refused}"
          {
            stdout: '',
            stderr: msg,
            exit: 126,
            error: 'unauthorized_recon_blocked',
            hint: msg
          }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::ToolGuard.placeholder?(text: '...')
              PWN::AI::Agent::ToolGuard.recon_authorized?
              PWN::AI::Agent::ToolGuard.coerce_args(args: { value: 'id' }, required: %w[command])
              #{self}.authors
          USAGE
        end
      end
    end
  end
end
