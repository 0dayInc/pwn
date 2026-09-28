# frozen_string_literal: true

module PWN
  module Plugins
    module REPL
      # Provider-reported token totals and explicitly configured USD estimates.
      module AIConsoleUsage
        # Accumulate one observer event per provider completion.
        class Tracker
          def initialize
            @lock = Mutex.new
            @input = 0
            @output = 0
            @cached = 0
            @cache_write = 0
            @calls = 0
            @latest = 0
            @priced = 0.0
            @priced_calls = 0
            @unpriced_calls = 0
          end

          def record(opts = {})
            usage = AIConsoleUsage.normalize(opts)
            price = AIConsoleUsage.estimate(opts.merge(usage: usage))
            @lock.synchronize do
              @input += usage[:input_tokens]
              @output += usage[:output_tokens]
              @cached += usage[:cached_tokens]
              @cache_write += usage[:cache_write_tokens]
              @calls += 1
              @latest = usage[:total_tokens]
              if price
                @priced += price
                @priced_calls += 1
              else
                @unpriced_calls += 1
              end
            end
            snapshot
          end

          def snapshot
            @lock.synchronize do
              status = if @calls.zero?
                         'no provider usage yet'
                       elsif @unpriced_calls.zero?
                         'estimated from configured USD rates'
                       elsif @priced_calls.zero?
                         'unavailable: no configured USD rate'
                       else
                         "partial: #{@unpriced_calls} call(s) have no configured rate"
                       end
              {
                input_tokens: @input, output_tokens: @output, cached_tokens: @cached,
                cache_write_tokens: @cache_write, total_tokens: @input + @output,
                latest_context_tokens: @latest, calls: @calls,
                estimated_cost_usd: @priced_calls.zero? ? nil : @priced,
                cost_status: status
              }
            end
          end
        end

        # Normalize a provider usage hash without double-counting cached tokens.
        public_class_method def self.normalize(opts = {})
          raw = opts[:usage].is_a?(Hash) ? opts[:usage] : opts
          details = raw[:input_tokens_details] || raw[:prompt_tokens_details] || {}
          cached = integer(value: details[:cached_tokens] || details[:cache_read_input_tokens] || raw[:cache_read_input_tokens])
          written = integer(value: details[:cache_creation_input_tokens] || raw[:cache_creation_input_tokens])
          input = integer(value: raw[:input_tokens] || raw[:prompt_tokens])
          output = integer(value: raw[:output_tokens] || raw[:completion_tokens])
          reasoning = integer(value: (raw[:output_tokens_details] || {})[:reasoning_tokens] || raw[:reasoning_tokens])
          output += reasoning if raw[:completion_tokens].nil? && raw[:output_tokens].nil?
          reported = raw[:total_tokens]
          total = reported.nil? ? input + output : integer(value: reported)
          { input_tokens: input, output_tokens: output, cached_tokens: cached, cache_write_tokens: written, total_tokens: total }
        end

        # Price only when every used component has an explicit finite USD rate.
        public_class_method def self.estimate(opts = {})
          usage = opts[:usage] || normalize(opts)
          rates = opts[:rates] || rates_for(engine: opts[:engine], model: opts[:model])
          return nil unless rates.is_a?(Hash)

          components = [
            [usage[:input_tokens] - usage[:cached_tokens] - usage[:cache_write_tokens], rates[:input_per_million]],
            [usage[:cached_tokens], rates[:cache_read_per_million] || rates[:input_per_million]],
            [usage[:cache_write_tokens], rates[:cache_write_per_million]],
            [usage[:output_tokens], rates[:output_per_million]]
          ]
          return nil if components.any? { |tokens, rate| tokens.to_i.positive? && !rate?(value: rate) }
          return nil if components.any? { |tokens, _rate| tokens.to_i.negative? }

          components.sum { |tokens, rate| tokens.to_i * rate.to_f / 1_000_000.0 }
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Normalize one provider usage report. Cached tokens are included in input, not added again.
            #{self}.normalize(
              usage: 'required - provider usage hash'
            )

            # Estimate USD only from explicit nonnegative rates; nil means unavailable, never zero.
            #{self}.estimate(
              usage: 'required - normalized or provider usage hash',
              rates: 'optional - input_per_million, output_per_million, cache_read_per_million, cache_write_per_million',
              engine: 'optional - provider used to read configured rates',
              model: 'optional - model key under that provider pricing hash'
            )

            # Return module authors.
            #{self}.authors
          "
        end

        private_class_method def self.integer(opts = {})
          opts[:value].to_i
        end

        private_class_method def self.rate?(opts = {})
          value = opts[:value]
          value.is_a?(Numeric) && value.finite? && value >= 0
        end

        private_class_method def self.rates_for(opts = {})
          engine = opts[:engine].to_s.to_sym
          model = opts[:model].to_s
          pricing = PWN::Env.dig(:ai, engine, :pricing) if defined?(PWN::Env)
          return nil unless pricing.is_a?(Hash)

          pricing[model.to_sym] || pricing[model]
        rescue StandardError
          nil
        end
      end
    end
  end
end
