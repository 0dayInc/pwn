# frozen_string_literal: true

module PWN
  module Plugins
    module REPL
      # Provider-reported token totals. USD comes from the active model's published
      # prices, then from explicitly configured rates. Missing prices stay unavailable.
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
            @catalog_priced = 0
            @configured_priced = 0
          end

          def record(opts = {})
            usage = AIConsoleUsage.normalize(opts)
            rates = opts[:rates] || AIConsoleUsage.send(:rates_for, engine: opts[:engine], model: opts[:model])
            price = AIConsoleUsage.estimate(usage: usage, rates: rates)
            source = rates.is_a?(Hash) ? rates[:source].to_s : ''
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
                if source == 'provider'
                  @catalog_priced += 1
                else
                  @configured_priced += 1
                end
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
                       elsif @unpriced_calls.zero? && @catalog_priced.positive? && @configured_priced.zero?
                         'estimated from provider model pricing'
                       elsif @unpriced_calls.zero? && @catalog_priced.positive?
                         'estimated from configured USD rates and provider model pricing'
                       elsif @unpriced_calls.zero?
                         'estimated from configured USD rates'
                       elsif @priced_calls.zero?
                         'unavailable: no provider or configured USD rate'
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
          cached = integer(value: details[:cached_tokens] || details[:cache_read_input_tokens] || raw[:cache_read_input_tokens] || raw[:cached_tokens])
          written = integer(value: details[:cache_creation_input_tokens] || raw[:cache_creation_input_tokens] || raw[:cache_write_tokens])
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
          raw = opts[:usage].is_a?(Hash) ? opts[:usage] : opts
          usage = normalize(usage: raw)
          rates = opts[:rates] || rates_for(engine: opts[:engine], model: opts[:model])
          return nil unless rates.is_a?(Hash)

          rates = apply_long_context(rates: rates, usage: usage)
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

            # Estimate USD from the active model's published prices, then configured rates.
            # nil means unavailable, never a fabricated zero.
            #{self}.estimate(
              usage: 'required - normalized or provider usage hash',
              rates: 'optional - input_per_million, output_per_million, cache_read_per_million, cache_write_per_million',
              engine: 'optional - provider whose get_model record publishes prices',
              model: 'optional - model id passed to that provider get_model'
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
          catalog = catalog_rates(opts)
          return catalog.merge(source: 'provider') if catalog

          configured = configured_rates(opts)
          configured&.merge(source: 'configured')
        rescue StandardError
          configured_rates(opts)&.merge(source: 'configured')
        end

        private_class_method def self.configured_rates(opts = {})
          engine = opts[:engine].to_s.to_sym
          model = opts[:model].to_s
          pricing = PWN::Env.dig(:ai, engine, :pricing) if defined?(PWN::Env)
          return nil unless pricing.is_a?(Hash)

          found = pricing[model.to_sym] || pricing[model]
          found.is_a?(Hash) ? found : nil
        rescue StandardError
          nil
        end

        private_class_method def self.catalog_rates(opts = {})
          rates = extract_rates(row: model_record(opts))
          return nil unless rates.is_a?(Hash)
          return nil unless rate?(value: rates[:input_per_million]) && rate?(value: rates[:output_per_million])
          return nil unless rates[:input_per_million].positive? && rates[:output_per_million].positive?

          rates
        end

        private_class_method def self.model_record(opts = {})
          engine = opts[:engine].to_s
          model = opts[:model].to_s
          return nil if engine.empty? || model.empty?

          key = "#{engine}\0#{model}"
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          hit = catalog_lock.synchronize { catalog_cache[key] }
          return hit[:row] if hit && hit[:until] > now

          klass = provider_class(engine: engine)
          row = klass.get_model(name: model, timeout: 8, fallback: false, non_interactive: true) if klass.respond_to?(:get_model)
          catalog_lock.synchronize do
            catalog_cache[key] = { until: now + (row.is_a?(Hash) ? 300 : 30), row: row }
          end
          row
        rescue StandardError
          nil
        end

        private_class_method def self.provider_class(opts = {})
          name = {
            'anthropic' => :Anthropic, 'gemini' => :Gemini, 'grok' => :Grok,
            'ollama' => :Ollama, 'openai' => :OpenAI, 'openwebui' => :OpenWebUI
          }[opts[:engine].to_s.downcase]
          return nil if name.nil? || !defined?(PWN::AI) || !PWN::AI.const_defined?(name)

          PWN::AI.const_get(name)
        end

        private_class_method def self.extract_rates(opts = {})
          row = opts[:row]
          return nil unless row.is_a?(Hash)

          xai = xai_rates(row: row)
          return xai if xai

          hashes = pricing_hashes(row: row)
          input = pick_rate(hashes: hashes, keys: %i[input_per_million input_per_1m input_per_mtok input prompt prompt_price input_cost_per_token input_token_cost])
          output = pick_rate(hashes: hashes, keys: %i[output_per_million output_per_1m output_per_mtok output completion completion_price output_cost_per_token output_token_cost])
          return nil unless input && output

          {
            input_per_million: input,
            output_per_million: output,
            cache_read_per_million: pick_rate(hashes: hashes, keys: %i[cache_read_per_million cached_input cached_input_per_million cache_read cached_prompt input_cache_read]),
            cache_write_per_million: pick_rate(hashes: hashes, keys: %i[cache_write_per_million cache_write cache_creation cache_creation_input_tokens])
          }.compact
        end

        # xAI publishes integer USD cents per 100 million tokens. Zero is unpublished, not free.
        private_class_method def self.xai_rates(opts = {})
          row = opts[:row]
          return nil unless row.key?(:prompt_text_token_price) || row.key?('prompt_text_token_price')

          input = xai_usd(value: row[:prompt_text_token_price] || row['prompt_text_token_price'])
          output = xai_usd(value: row[:completion_text_token_price] || row['completion_text_token_price'])
          return nil unless input && output

          rates = {
            input_per_million: input,
            output_per_million: output,
            cache_read_per_million: xai_usd(value: row[:cached_prompt_text_token_price] || row['cached_prompt_text_token_price'])
          }
          threshold = numeric_value(value: row[:long_context_threshold] || row[:prompt_token_price_threshold])
          if threshold&.positive?
            rates[:long_context_tokens] = threshold
            rates[:long_input_per_million] = xai_usd(value: row[:prompt_text_token_price_long_context])
            rates[:long_output_per_million] = xai_usd(value: row[:completion_text_token_price_long_context])
            rates[:long_cache_read_per_million] = xai_usd(value: row[:cached_prompt_text_token_price_long_context])
          end
          rates.compact
        end

        private_class_method def self.xai_usd(opts = {})
          number = numeric_value(value: opts[:value])
          return nil unless number&.finite? && number.positive?

          number / 10_000.0
        end

        private_class_method def self.apply_long_context(opts = {})
          rates = opts[:rates]
          threshold = rates[:long_context_tokens]
          return rates unless threshold.is_a?(Numeric) && threshold.positive?
          return rates if opts[:usage][:input_tokens].to_i < threshold

          swapped = rates.dup
          swapped[:input_per_million] = rates[:long_input_per_million] if rate?(value: rates[:long_input_per_million])
          swapped[:output_per_million] = rates[:long_output_per_million] if rate?(value: rates[:long_output_per_million])
          swapped[:cache_read_per_million] = rates[:long_cache_read_per_million] if rate?(value: rates[:long_cache_read_per_million])
          swapped
        end

        private_class_method def self.pricing_hashes(opts = {})
          row = opts[:row]
          nested = [
            row, row[:pricing], row['pricing'], row[:price], row[:costs],
            row.dig(:info, :pricing), row.dig(:info, :meta, :pricing), row.dig(:info, 'meta', 'pricing'),
            row.dig(:metadata, :pricing), row.dig(:details, :pricing)
          ]
          nested.grep(Hash)
        end

        private_class_method def self.pick_rate(opts = {})
          opts[:hashes].each do |hash|
            opts[:keys].each do |key|
              value = hash[key] || hash[key.to_s]
              rate = money_per_million(value: value, key: key)
              return rate if rate
            end
          end
          nil
        end

        private_class_method def self.money_per_million(opts = {})
          value = opts[:value]
          if value.is_a?(Hash)
            unit = (value[:unit] || value['unit'] || value[:per] || value['per']).to_s
            value = value[:usd] || value['usd'] || value[:amount] || value['amount'] || value[:price] || value['price']
            opts = opts.merge(value: value, key: unit.empty? ? opts[:key] : unit)
          end
          number = numeric_value(value: opts[:value])
          return nil unless number&.finite? && number.positive?

          key = opts[:key].to_s
          per_million = key.match?(/per_million|per_1m|per_mtok/)
          per_token = key.match?(/per_token|token_cost|cost_per_token/) || (!per_million && number < 0.001)
          per_token ? number * 1_000_000 : number
        end

        private_class_method def self.numeric_value(opts = {})
          value = opts[:value]
          return value if value.is_a?(Numeric)
          return nil unless value.is_a?(String) && value.match?(/\A-?\d+(\.\d+)?\z/)

          Float(value)
        rescue StandardError
          nil
        end

        private_class_method def self.catalog_lock
          @catalog_lock ||= Mutex.new
        end

        private_class_method def self.catalog_cache
          @catalog_cache ||= {}
        end
      end
    end
  end
end
