# frozen_string_literal: true

require 'json'

module PWN
  module AI
    # Shared catalog lookup for provider model records. Each provider still
    # fetches its own payload; this only finds one named row without a second
    # network call when the caller already has the list.
    module ModelCatalog
      # Return the catalog row whose id, slug, name, or model matches name.
      public_class_method def self.find_row(opts = {})
        name = opts[:name].to_s.strip
        return nil if name.empty?

        rows = catalog_rows(models: opts[:models])
        wanted = name.delete_prefix('models/')
        rows.find do |row|
          next false unless row.is_a?(Hash)

          ids = [
            row[:id], row['id'], row[:slug], row['slug'], row[:name], row['name'],
            row[:model], row['model'], row[:display_name], row['display_name']
          ].compact.map { |value| value.to_s.delete_prefix('models/') }
          aliases = row[:aliases] || row['aliases'] || []
          ids.concat(Array(aliases).map(&:to_s))
          ids.any? { |value| value == name || value == wanted }
        end
      end

      # Flatten the list shapes get_models already returns.
      public_class_method def self.catalog_rows(opts = {})
        raw = opts[:models]
        case raw
        when Array then raw
        when Hash then raw[:data] || raw[:models] || raw['data'] || raw['models'] || []
        else []
        end
      end

      # True when the hash is a model record rather than an error object.
      public_class_method def self.model_row?(opts = {})
        row = opts[:row]
        return false unless row.is_a?(Hash)

        %i[id slug name model].any? { |key| !(row[key] || row[key.to_s]).to_s.strip.empty? }
      end

      # Parse a REST body into a Hash or Array. Error strings are not catalogs.
      public_class_method def self.parse_row(opts = {})
        raw = opts[:raw]
        return raw if raw.is_a?(Hash) || raw.is_a?(Array)
        return nil if raw.nil?
        return nil unless raw.is_a?(String) || raw.respond_to?(:to_str)

        parsed = JSON.parse(raw.to_s, symbolize_names: true)
        parsed.is_a?(Hash) || parsed.is_a?(Array) ? parsed : nil
      rescue JSON::ParserError
        nil
      end

      # Short, non-interactive hop so a price lookup cannot prompt or retry for minutes.
      public_class_method def self.lookup_opts(opts = {})
        timeout = opts[:timeout].to_i
        timeout = 15 unless timeout.positive?
        {
          timeout: timeout,
          non_interactive: opts.fetch(:non_interactive, true),
          quiet: true,
          spinner: false
        }
      end

      public_class_method def self.authors
        'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
      end

      public_class_method def self.help
        puts "USAGE:
          # Find one catalog row by id, slug, name, model, or alias.
          #{self}.find_row(
            models: 'required - get_models payload',
            name: 'required - model id'
          )

          # Flatten a provider catalog into row hashes.
          #{self}.catalog_rows(
            models: 'required - get_models payload'
          )

          # True when the hash is a model record rather than an error object.
          #{self}.model_row?(
            row: 'required - catalog row hash to test'
          )

          # Parse one REST model body. Error strings are not catalogs.
          #{self}.parse_row(
            raw: 'required - response body'
          )

          # Short non-interactive options for a price lookup.
          #{self}.lookup_opts(
            timeout: 'optional - seconds (default 15, one attempt)',
            non_interactive: 'optional - never prompt (default true)'
          )

          # Return module authors.
          #{self}.authors
        "
      end
    end
  end
end
