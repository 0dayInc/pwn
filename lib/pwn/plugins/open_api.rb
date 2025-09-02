# frozen_string_literal: true

require 'yaml'
require 'json'
require 'uri'
require 'fileutils'
require 'json_schemer'
require 'rest-client'

module PWN
  module Plugins
    # Module to interact with OpenAPI specifications, merging multiple specs
    # while resolving schema dependencies and ensuring OpenAPI compliance.
    module OpenAPI
      # Supported Method Parameters:
      # openapi_spec = PWN::Plugins::OpenAPI.generate_spec(
      #   spec_paths: 'required - array of OpenAPI file paths to merge',
      #   base_url: 'required - base URL for OpenAPI endpoints (e.g., http://fqdn.com)',
      #   output_json_path: 'optional - path to save the merged OpenAPI JSON file',
      #   target_version: 'optional - target OpenAPI version (default: 3.0.3)',
      #   debug: 'optional - boolean to enable debug logging (default: false)'
      # )
      def self.generate_spec(opts = {})
        spec_paths = opts[:spec_paths] ||= []
        raise ArgumentError, 'spec_paths must be a non-empty array' if spec_paths.empty?

        base_url = opts[:base_url]
        raise ArgumentError, 'base_url is required' if base_url.nil? || base_url.empty?

        target_version = opts[:target_version] ||= '3.0.3'
        raise ArgumentError, "Unsupported OpenAPI version: #{target_version}" unless %w[3.0.0 3.0.1 3.0.2 3.0.3 3.1.0].include?(target_version)

        output_json_path = opts[:output_json_path]
        raise ArgumentError, 'output_json_path is required' if output_json_path.nil? || output_json_path.empty?

        debug = opts[:debug] || false
        validation_fixes = []

        begin
          # Parse base_url to extract host and default base path
          normalized_base_url, default_base_path = normalize_url(url: base_url)
          default_base_path ||= '' # Fallback if base_url has no path
          log("Using normalized base URL: #{normalized_base_url}, default base path: #{default_base_path}", debug: debug)

          # Load and parse all OpenAPI files
          specs = {}
          spec_paths.each do |path|
            raise Errno::ENOENT, "OpenAPI file not found: #{path}" unless File.exist?(path)

            begin
              case File.extname(path).downcase
              when '.yaml', '.yml'
                specs[path] = YAML.safe_load_file(path, permitted_classes: [Symbol, Date, Time], aliases: true)
              when '.json'
                specs[path] = JSON.parse(File.read(path))
              else
                raise "Unsupported file type: #{path} - only .yaml, .yml, and .json files"
              end
            rescue YAML::SyntaxError, JSON::ParserError => e
              raise "Error parsing OpenAPI file #{path}: #{e.message}"
            end
          end

          specs.each do |path, spec|
            # Pre-validate input specs
            if spec['paths'].is_a?(Hash)
              spec['paths'].each do |endpoint, path_item|
                next unless path_item.is_a?(Hash)

                path_item.each do |method, operation|
                  next unless operation.is_a?(Hash) && operation['parameters'].is_a?(Array)

                  param_names = operation['parameters'].map { |p| p['name'] }.compact
                  duplicates = param_names.tally.select { |_, count| count > 1 }.keys
                  raise "Duplicate parameters found in #{path} for path '#{endpoint}' (method: #{method}): #{duplicates.join(', ')}" unless duplicates.empty?

                  operation['parameters'].each do |param|
                    next unless param['in'] == 'path'

                    raise "Path parameter #{param['name']} in #{path} (path: #{endpoint}, method: #{method}) must have a schema" unless param['schema'].is_a?(Hash)
                  end
                end
              end
            end

            # Clean up null schemas in each spec
            clean_null_schemas(spec, path, '', validation_fixes, debug)

            # Fix invalid header definitions
            if spec['components']&.key?('headers')
              spec['components']['headers'].each do |header_name, header|
                next unless header.is_a?(Hash)

                if header.key?('name') || header.key?('in')
                  validation_fixes << {
                    path: "/components/headers/#{header_name}",
                    error: "Invalid properties 'name' or 'in' in header",
                    fix: "Removed 'name' and 'in' from header definition"
                  }
                  log("Fixing header '#{header_name}' in #{path}: Removing invalid 'name' and 'in' properties", debug: debug)
                  header.delete('name')
                  header.delete('in')
                end
                next unless header['schema'].nil?

                validation_fixes << {
                  path: "/components/headers/#{header_name}",
                  error: 'Header schema is null',
                  fix: 'Added default schema { type: string }'
                }
                log("Fixing header '#{header_name}' in #{path}: Replacing null schema with default { type: string }", debug: debug)
                header['schema'] = { 'type' => 'string' }
              end
            end

            # Fix schema items for arrays (e.g., mediaServers)
            next unless spec['components']&.key?('schemas')

            spec['components']['schemas'].each do |schema_name, schema|
              fix_array_items(schema, path, "/components/schemas/#{schema_name}", validation_fixes, debug)
            end
          end

          # # Pre-validate input specs
          # specs.each do |path, spec|
          #   next unless spec['paths'].is_a?(Hash)

          #   spec['paths'].each do |endpoint, path_item|
          #     next unless path_item.is_a?(Hash)

          #     path_item.each do |method, operation|
          #       next unless operation.is_a?(Hash) && operation['parameters'].is_a?(Array)

          #       param_names = operation['parameters'].map { |p| p['name'] }.compact
          #       duplicates = param_names.tally.select { |_, count| count > 1 }.keys
          #       raise "Duplicate parameters found in #{path} for path '#{endpoint}' (method: #{method}): #{duplicates.join(', ')}" unless duplicates.empty?

          #       operation['parameters'].each do |param|
          #         next unless param['in'] == 'path'

          #         raise "Path parameter #{param['name']} in #{path} (path: #{endpoint}, method: #{method}) must have a schema" unless param['schema'].is_a?(Hash)
          #       end
          #     end
          #   end
          # end

          # # Fix invalid header definitions
          # specs.each do |path, spec|
          #   # Clean up null schemas in each spec
          #   clean_null_schemas(spec, path, '', validation_fixes, debug)

          #   next unless spec['components']&.key?('headers')

          #   spec['components']['headers'].each do |header_name, header|
          #     next unless header.is_a?(Hash)

          #     if header.key?('name') || header.key?('in')
          #       validation_fixes << {
          #         path: "/components/headers/#{header_name}",
          #         error: "Invalid properties 'name' or 'in' in header",
          #         fix: "Removed 'name' and 'in' from header definition"
          #       }
          #       log("Fixing header '#{header_name}' in #{path}: Removing invalid 'name' and ''in' properties", debug: debug)
          #       header.delete('name')
          #       header.delete('in')
          #     end
          #     next unless header['schema'].nil?

          #     validation_fixes << {
          #       path: "/components/headers/#{header_name}",
          #       error: 'Header schema is null',
          #       fix: 'Added default schema { type: string }'
          #     }
          #     log("Fixing header '#{header_name}' in #{path}: Replacing null schema with default { type: string }", debug: debug)
          #     header['schema'] = { 'type' => 'string' }
          #   end
          # end

          # Fix schema items for arrays (e.g., mediaServers)
          # specs.each do |path, spec|
          #   next unless spec['components']&.key?('schemas')

          #   spec['components']['schemas'].each do |schema_name, schema|
          #     fix_array_items(schema, path, "/components/schemas/#{schema_name}", validation_fixes, debug)
          #   end
          # end

          # Determine dependencies based on $ref
          dependencies = {}
          specs.each do |path, spec|
            dependencies[path] = [] # Initialize empty array for all paths
            refs = extract_refs(spec: spec, spec_paths: spec_paths)
            refs.each do |ref|
              dep_path = resolve_ref_path(ref: ref, spec_paths: spec_paths, referencing_file: path)
              dependencies[path] << dep_path if specs.key?(dep_path) && dep_path != path
            end
          end

          # Sort files by dependencies
          ordered_paths, cycle_info = topological_sort(dependencies: dependencies, spec_paths: spec_paths)
          if cycle_info
            log("Cyclic dependencies detected: #{cycle_info.join(' -> ')}. Processing files in provided order.", debug: debug)
            ordered_paths = spec_paths
          end

          # Initialize merged specification with a single server
          merged_spec = {
            'openapi' => target_version,
            'info' => {
              'title' => 'Merged OpenAPI Specification',
              'version' => '1.0.0'
            },
            'servers' => [{ 'url' => normalized_base_url, 'description' => 'Default server' }],
            'paths' => {},
            'components' => { 'schemas' => {}, 'headers' => {} },
            'tags' => [],
            'security' => []
          }

          # Collect base paths from server URLs
          server_base_paths = {}

          ordered_paths.each do |path|
            spec = specs[path]
            unless spec.is_a?(Hash)
              log("Skipping #{path}: Invalid OpenAPI specification", debug: debug)
              next
            end

            log("Warning: #{path} uses OpenAPI version #{spec['openapi']}, which may not be compatible with target version #{target_version}", debug: debug) if spec['openapi'] && !spec['openapi'].start_with?(target_version.split('.')[0..1].join('.'))

            if spec['definitions'] && target_version.start_with?('3.')
              log("Migrating OpenAPI 2.0 'definitions' to 'components/schemas' for #{path}", debug: debug)
              spec['components'] ||= {}
              spec['components']['schemas'] = spec.delete('definitions')
            end

            resolved_spec = resolve_refs(spec: spec, specs: specs, spec_paths: spec_paths, referencing_file: path, debug: debug)

            # Process server URLs
            selected_server = nil
            server_base_path = nil
            absolute_url = nil

            if resolved_spec['servers']
              servers = resolved_spec['servers'].is_a?(Array) ? resolved_spec['servers'] : [resolved_spec['servers']]
              # Prioritize server with non-empty path
              selected_server = servers.find { |s| s.is_a?(Hash) && s['url'] && !URI.parse(s['url']).path.empty? } ||
                                servers.find { |s| s.is_a?(Hash) && s['description'] } ||
                                servers.first

              server_url = selected_server.is_a?(Hash) ? selected_server['url'] : selected_server
              if server_url.is_a?(String)
                absolute_url, server_base_path = normalize_url(url: server_url, base_url: normalized_base_url)
                server_base_path ||= default_base_path
                log("Selected server URL: #{server_url}, normalized: #{absolute_url}, base path: #{server_base_path} for #{path}", debug: debug)
                server_obj = selected_server.is_a?(Hash) ? selected_server.merge('url' => absolute_url) : { 'url' => absolute_url }
                unless merged_spec['servers'].any? { |s| s['url'] == absolute_url }
                  merged_spec['servers'] << server_obj
                  # Update default_base_path if servers length > 1
                  if merged_spec['servers'].length > 1
                    last_server_url = merged_spec['servers'].last['url']
                    new_base_path = URI.parse(last_server_url).path&.sub(%r{^/+}, '')&.sub(%r{/+$}, '')
                    default_base_path = new_base_path || default_base_path
                    log("Updated default_base_path to '#{default_base_path}' based on last server: #{last_server_url}", debug: debug)
                  end
                end
              else
                log("No valid server URL in #{path}, using default base path: #{default_base_path}", debug: debug)
                absolute_url = normalized_base_url
                server_base_path = default_base_path
              end
            else
              # Check dependencies for server URLs
              (dependencies[path] || []).each do |dep_path|
                dep_spec = specs[dep_path]
                next unless dep_spec['servers']

                dep_servers = dep_spec['servers'].is_a?(Array) ? dep_spec['servers'] : [dep_spec['servers']]
                dep_server = dep_servers.find { |s| s.is_a?(Hash) && s['url'] && !URI.parse(s['url']).path.empty? }
                next unless dep_server

                dep_server_url = dep_server['url']
                absolute_url, server_base_path = normalize_url(url: dep_server_url, base_url: normalized_base_url)
                server_base_path ||= default_base_path
                log("Using dependency server URL: #{dep_server_url}, normalized: #{absolute_url}, base path: #{server_base_path} for #{path}", debug: debug)
                server_obj = dep_server.merge('url' => absolute_url)
                unless merged_spec['servers'].any? { |s| s['url'] == absolute_url }
                  merged_spec['servers'] << server_obj
                  # Update default_base_path if servers length > 1
                  if merged_spec['servers'].length > 1
                    last_server_url = merged_spec['servers'].last['url']
                    new_base_path = URI.parse(last_server_url).path&.sub(%r{^/+}, '')&.sub(%r{/+$}, '')
                    default_base_path = new_base_path || default_base_path
                    log("Updated default_base_path to '#{default_base_path}' based on last server: #{last_server_url}", debug: debug)
                  end
                end
                break
              end
              unless absolute_url
                log("No servers defined in #{path} or dependencies, using default base path: #{default_base_path}", debug: debug)
                absolute_url = normalized_base_url
                server_base_path = default_base_path
              end
            end
            server_base_paths[path] = server_base_path

            # Normalize paths
            if resolved_spec['paths'].is_a?(Hash)
              resolved_spec['paths'] = validate_path_parameters(
                resolved_spec['paths'],
                path,
                server_base_path: server_base_path,
                debug: debug
              )
            end

            merged_spec['openapi'] = [resolved_spec['openapi'], target_version].max if resolved_spec['openapi']

            if resolved_spec['info'].is_a?(Hash)
              merged_spec['info'] = deep_merge(hash1: merged_spec['info'], hash2: resolved_spec['info'])
              raise "Missing required info.title in #{path}" unless merged_spec['info']['title']
              raise "Missing required info.version in #{path}" unless merged_spec['info']['version']
            end

            if resolved_spec['paths'].is_a?(Hash)
              resolved_paths = resolved_spec['paths'].transform_keys do |endpoint|
                effective_base_path = server_base_paths[path]
                # Strip redundant base path before combining
                normalized_endpoint = endpoint.to_s.sub(%r{^/+}, '').sub(%r{/+$}, '')
                if effective_base_path && !effective_base_path.empty?
                  prefix_pattern = Regexp.new("^#{Regexp.escape(effective_base_path)}/")
                  while normalized_endpoint.match?(prefix_pattern)
                    normalized_endpoint = normalized_endpoint.sub(prefix_pattern, '')
                    log("Stripped '#{effective_base_path}' from endpoint '#{endpoint}' to '#{normalized_endpoint}' during merge in #{path}", debug: debug)
                  end
                end
                normalized_endpoint = '/' if normalized_endpoint.empty?
                combined_path = combine_paths(effective_base_path, normalized_endpoint)
                log("Merging path '#{endpoint}' as '#{combined_path}' from #{path}", debug: debug)
                combined_path
              end
              merged_spec['paths'].merge!(resolved_paths) do |api_endpoint, _existing, new|
                log("Path '#{api_endpoint}' in #{path} conflicts with existing path. Overwriting.", debug: debug)
                new
              end
            end

            merged_spec['components'] = deep_merge(hash1: merged_spec['components'], hash2: resolved_spec['components']) if resolved_spec['components'].is_a?(Hash)

            if resolved_spec['tags'].is_a?(Array)
              resolved_spec['tags'].each do |tag|
                merged_spec['tags'] << tag unless merged_spec['tags'].include?(tag)
              end
            end

            next unless resolved_spec['security'].is_a?(Array)

            resolved_spec['security'].each do |security|
              merged_spec['security'] << security unless merged_spec['security'].include?(security)
            end
          end

          # Filter servers to keep only those with paths matching the first folder in paths
          if merged_spec['paths'].any?
            path_first_folders = merged_spec['paths'].keys.map do |path|
              path_segments = path.sub(%r{^/+}, '').split('/')
              path_segments.first if path_segments.any?
            end.compact.uniq
            log("First folders in paths: #{path_first_folders}", debug: debug)

            if path_first_folders.any?
              merged_spec['servers'] = merged_spec['servers'].select do |server|
                server_url = server['url']
                server_path = URI.parse(server_url).path&.sub(%r{^/+}, '')&.sub(%r{/+$}, '')
                server_path && path_first_folders.include?(server_path)
              end
              log("Filtered servers to: #{merged_spec['servers'].map { |s| s['url'] }}", debug: debug)
            end
          end

          # Ensure at least one server remains
          if merged_spec['servers'].empty?
            merged_spec['servers'] = [{ 'url' => normalized_base_url, 'description' => 'Default server' }]
            log("No servers matched path prefixes. Reverted to default: #{normalized_base_url}", debug: debug)
          end

          # Remove server path prefixes from path keys
          merged_spec = remove_server_path_prefixes(merged_spec, debug: debug)

          # Clean up null schemas in the merged spec
          clean_null_schemas(merged_spec, 'merged_spec', '', validation_fixes, debug)

          merged_spec, schema_validation_errors = validate_openapi_spec(
            merged_spec: merged_spec,
            target_version: target_version,
            debug: debug
          )

          unless validation_fixes.empty? && schema_validation_errors.empty?
            merged_spec['x-validation-fixes'] = validation_fixes + schema_validation_errors
            log("Added validation fixes to spec: #{merged_spec['x-validation-fixes'].map { |f| f[:error] }.join(', ')}", debug: debug)
          end

          FileUtils.mkdir_p(File.dirname(output_json_path))
          File.write(output_json_path, JSON.pretty_generate(merged_spec))
          log("Merged OpenAPI specification written to: #{output_json_path}", debug: debug)

          { individual_specs: specs, merged_spec: merged_spec }
        rescue Errno::ENOENT => e
          raise "Error accessing file: #{e.message}"
        rescue StandardError => e
          raise "Unexpected error: #{e.message}"
        end
      end

      # Recursively clean null schemas
      private_class_method def self.clean_null_schemas(spec, file_path, current_path, validation_fixes, debug)
        case spec
        when Hash
          spec.each do |key, value|
            new_path = current_path.empty? ? key : "#{current_path}/#{key}"
            if key == 'schema' && value.nil?
              validation_fixes << {
                path: new_path,
                error: 'Schema is null',
                fix: 'Replaced with default schema { type: string }'
              }
              log("Fixing null schema at #{new_path} in #{file_path}: Replacing with default { type: string }", debug: debug)
              spec[key] = { 'type' => 'string' }
            else
              clean_null_schemas(value, file_path, new_path, validation_fixes, debug)
            end
          end
        when Array
          spec.each_with_index do |item, i|
            clean_null_schemas(item, file_path, "#{current_path}/#{i}", validation_fixes, debug)
          end
        end
      end

      private_class_method def self.fix_array_items(schema, file_path, schema_path, validation_fixes, debug)
        return unless schema.is_a?(Hash)

        if schema['type'] == 'array'
          if schema['items'].nil?
            validation_fixes << {
              path: "#{schema_path}/items",
              error: 'Array schema missing items',
              fix: 'Added default items { type: string }'
            }
            log("Fixing missing items at #{schema_path}/items in #{file_path}: Adding default { type: string }", debug: debug)
            schema['items'] = { 'type' => 'string' }
          elsif schema['items'].is_a?(Array)
            validation_fixes << {
              path: "#{schema_path}/items",
              error: 'Array items must be an object, not an array',
              fix: 'Converted items to object with type: string'
            }
            log("Fixing invalid array items at #{schema_path}/items in #{file_path}: Converting array to object", debug: debug)
            schema['items'] = { 'type' => 'string' }
          end
        end

        if schema['properties'].is_a?(Hash)
          schema['properties'].each do |prop_name, prop_schema|
            fix_array_items(prop_schema, file_path, "#{schema_path}/properties/#{prop_name}", validation_fixes, debug)
          end
        end

        %w[allOf anyOf oneOf].each do |keyword|
          next unless schema[keyword].is_a?(Array)

          schema[keyword].each_with_index do |sub_schema, i|
            fix_array_items(sub_schema, file_path, "#{schema_path}/#{keyword}/#{i}", validation_fixes, debug)
          end
        end

        fix_array_items(schema['items'], file_path, "#{schema_path}/items", validation_fixes, debug) if schema['items'].is_a?(Hash)
      end

      private_class_method def self.combine_paths(base_path, endpoint)
        base_path = base_path.to_s.sub(%r{^/+}, '').sub(%r{/+$}, '')
        endpoint = endpoint.to_s.sub(%r{^/+}, '').sub(%r{/+$}, '')
        combined_path = if base_path.empty?
                          endpoint.empty? ? '/' : "/#{endpoint}"
                        elsif endpoint.empty?
                          "/#{base_path}"
                        else
                          "/#{base_path}/#{endpoint}"
                        end
        combined_path.gsub(%r{/+}, '/')
      end

      private_class_method def self.validate_openapi_spec(opts = {})
        merged_spec = opts[:merged_spec]
        target_version = opts[:target_version] || '3.0.3'
        debug = opts[:debug] || false
        validation_errors = []

        schema_urls = {
          '3.0.0' => 'https://spec.openapis.org/oas/3.0/schema/2021-09-28',
          '3.0.1' => 'https://spec.openapis.org/oas/3.0/schema/2021-09-28',
          '3.0.2' => 'https://spec.openapis.org/oas/3.0/schema/2021-09-28',
          '3.0.3' => 'https://spec.openapis.org/oas/3.0/schema/2021-09-28',
          '3.1.0' => 'https://spec.openapis.org/oas/3.1/schema/2021-09-28'
        }

        schema_url = schema_urls[target_version]
        raise "No schema available for OpenAPI version #{target_version}" unless schema_url

        begin
          schema = JSON.parse(RestClient.get(schema_url))
          schemer = JSONSchemer.schema(schema)

          unless schemer.valid?(merged_spec)
            schemer.validate(merged_spec).each do |error|
              validation_errors << {
                path: error['data_pointer'],
                error: error['error'],
                fix: 'Validation failed; manual correction required'
              }
              log("Validation error: #{error['error']} at #{error['data_pointer']}", debug: debug)
            end
          end
          [merged_spec, validation_errors]
        rescue OpenURI::HTTPError => e
          log("Failed to fetch OpenAPI schema from #{schema_url}: #{e.message}", debug: debug)
          raise "Failed to validate OpenAPI specification: #{e.message}"
        rescue StandardError => e
          log("Error validating OpenAPI specification: #{e.message}", debug: debug)
          raise "Failed to validate OpenAPI specification: #{e.message}"
        end
      end

      private_class_method def self.validate_path_parameters(paths, file_path, opts = {})
        debug = opts[:debug] || false
        server_base_path = opts[:server_base_path]&.sub(%r{^/+}, '')&.sub(%r{/+$}, '')

        transformed_paths = {}
        paths.each do |endpoint, path_item|
          next unless path_item.is_a?(Hash)

          # Normalize endpoint by stripping redundant server_base_path

          normalized_endpoint = endpoint.to_s.sub(%r{^/+}, '').sub(%r{/+$}, '')
          if server_base_path && !server_base_path.empty?
            prefix_pattern = Regexp.new("^#{Regexp.escape(server_base_path)}/")
            while normalized_endpoint.match?(prefix_pattern)
              normalized_endpoint = normalized_endpoint.sub(prefix_pattern, '')
              log("Stripped '#{server_base_path}' from endpoint '#{endpoint}' to '#{normalized_endpoint}' in #{file_path}", debug: debug)
            end
          end
          normalized_endpoint = '/' if normalized_endpoint.empty?

          log("Validating path '#{endpoint}' as '#{normalized_endpoint}' in #{file_path}", debug: debug)

          path_params = path_item['parameters']&.select { |p| p['in'] == 'path' }&.map { |p| p['name'] }&.compact || []

          path_item.each do |method, operation|
            next unless operation.is_a?(Hash)

            operation_params = operation['parameters']&.select { |p| p['in'] == 'path' }&.map { |p| p['name'] }&.compact || []
            all_params = (path_params + operation_params).uniq
            required_params = normalized_endpoint.scan(/\{([^}]+)\}/).flatten

            missing_params = required_params - all_params
            unless missing_params.empty?
              log("In #{file_path}, path '#{normalized_endpoint}' (method: #{method}) has undeclared path parameters: #{missing_params.join(', ')}. Adding default definitions.", debug: debug)
              operation['parameters'] ||= []
              missing_params.each do |param|
                operation['parameters'] << {
                  'name' => param,
                  'in' => 'path',
                  'required' => true,
                  'schema' => { 'type' => 'string' }
                }
              end
            end

            operation['parameters']&.each do |param|
              next unless param['in'] == 'path'
              raise "Path parameter #{param['name']} in #{file_path} (path: #{normalized_endpoint}, method: #{method}) must be required" unless param['required']
              next unless param['schema'].nil?

              log("Path parameter #{param['name']} in #{file_path} (path: #{normalized_endpoint}, method: #{method}) has null schema. Adding default schema (type: string).", debug: debug)
              validation_fixes << {
                path: "#{normalized_endpoint}/parameters/#{param['name']}",
                error: 'Path parameter schema is null',
                fix: 'Added default schema { type: string }'
              }
              param['schema'] = { 'type' => 'string' }
            end

            param_names = operation['parameters']&.map { |p| p['name'] }&.compact || []
            duplicates = param_names.tally.select { |_, count| count > 1 }.keys
            raise "Duplicate parameters found in #{file_path} for path '#{normalized_endpoint}' (method: #{method}): #{duplicates.join(', ') || 'unknown'}" unless duplicates.empty?
          end
          transformed_paths[normalized_endpoint] = path_item
        end
        transformed_paths
      end

      private_class_method def self.remove_server_path_prefixes(merged_spec, debug: false)
        return merged_spec unless merged_spec['paths'].is_a?(Hash) && merged_spec['servers'].is_a?(Array)

        transformed_paths = {}
        servers = merged_spec['servers']
        paths = merged_spec['paths']

        paths.each do |path, path_item|
          normalized_path = path.sub(%r{^/+}, '').sub(%r{/+$}, '')
          path_segments = normalized_path.split('/').reject(&:empty?)
          next unless path_segments.any?

          first_segment = path_segments.first
          matching_server = servers.find do |server|
            server_url = server['url']
            begin
              server_path = URI.parse(server_url).path&.sub(%r{^/+}, '')&.sub(%r{/+$}, '')
              server_path == first_segment
            rescue URI::InvalidURIError
              false
            end
          end

          if matching_server
            new_path = path_segments[1..-1].join('/')
            new_path = '/' if new_path.empty?
            new_path = "/#{new_path}" unless new_path.start_with?('/')
            log("Removing server path prefix '#{first_segment}' from path '#{path}' to '#{new_path}'", debug: debug)
            transformed_paths[new_path] = path_item
          else
            transformed_paths[path] = path_item
          end
        end

        merged_spec['paths'] = transformed_paths
        merged_spec
      end

      private_class_method def self.normalize_url(opts = {})
        url = opts[:url]
        base_url = opts[:base_url]
        return [url, nil] if url.nil? || url.empty?

        begin
          uri = URI.parse(url)
          if uri.absolute? && uri.scheme && uri.host
            base_path = uri.path.empty? ? nil : uri.path.sub(%r{^/+}, '').sub(%r{/+$}, '')
            [uri.to_s.sub(%r{/+$}, ''), base_path]
          elsif base_url && !base_url.empty?
            base_uri = URI.parse(base_url)
            uri = base_uri.merge(url)
            base_path = uri.path.empty? ? nil : uri.path.sub(%r{^/+}, '').sub(%r{/+$}, '')
            [uri.to_s.sub(%r{/+$}, ''), base_path]
          else
            raise URI::InvalidURIError, "Relative URL '#{url}' provided without a valid base_url"
          end
        rescue URI::InvalidURIError => e
          raise "Invalid server URL '#{url}': #{e.message}"
        end
      end

      private_class_method def self.resolve_refs(opts = {})
        spec = opts[:spec]
        specs = opts[:specs]
        spec_paths = opts[:spec_paths] ||= []
        referencing_file = opts[:referencing_file] || 'unknown'
        depth = opts[:depth] ||= 0
        debug = opts[:debug] || false
        max_depth = 50

        raise "Maximum $ref resolution depth exceeded in #{referencing_file}" if depth > max_depth

        case spec
        when Hash
          resolved = {}
          spec.each do |key, value|
            if key == '$ref' && value.is_a?(String)
              ref_path, json_pointer = value.split('#', 2)
              json_pointer ||= ''
              if ref_path.empty? || ref_path == '#'
                log("Resolving internal $ref: #{value} in #{referencing_file}", debug: debug)
                target = resolve_json_pointer(spec, json_pointer, referencing_file, referencing_file)
                if target.nil?
                  resolved[key] = value
                else
                  resolved = resolve_refs(spec: target, specs: specs, spec_paths: spec_paths, referencing_file: referencing_file, depth: depth + 1, debug: debug)
                end
              else
                matched_path = resolve_ref_path(ref: ref_path, spec_paths: spec_paths, referencing_file: referencing_file)
                unless specs.key?(matched_path)
                  log("Unable to resolve external $ref: #{value} from #{referencing_file}", debug: debug)
                  begin
                    return value unless File.exist?(ref_path)

                    case File.extname(ref_path).downcase
                    when '.yaml', '.yml'
                      specs[ref_path] = YAML.safe_load_file(ref_path, permitted_classes: [Symbol, Date, Time], aliases: true)
                      spec_paths << ref_path unless spec_paths.include?(ref_path)
                    when '.json'
                      specs[ref_path] = JSON.parse(File.read(ref_path))
                    else
                      log("Unsupported file type for $ref: #{ref_path} from #{referencing_file}", debug: debug)
                      return value
                    end
                  rescue StandardError => e
                    log("Failed to load external $ref #{ref_path}: #{e.message} from #{referencing_file}", debug: debug)
                    return value
                  end
                end
                ref_spec = specs[matched_path]
                target = json_pointer.empty? ? ref_spec : resolve_json_pointer(ref_spec, json_pointer, matched_path, referencing_file)
                if target.nil?
                  log("Invalid JSON pointer #{json_pointer} in #{matched_path} from #{referencing_file}", debug: debug)
                  resolved[key] = value
                else
                  resolved = resolve_refs(spec: target, specs: specs, spec_paths: spec_paths, referencing_file: matched_path, depth: depth + 1, debug: debug)
                end
              end
            else
              resolved[key] = resolve_refs(spec: value, specs: specs, spec_paths: spec_paths, referencing_file: referencing_file, depth: depth, debug: debug)
            end
          end
          resolved
        when Array
          spec.map { |item| resolve_refs(spec: item, specs: specs, spec_paths: spec_paths, referencing_file: referencing_file, depth: depth, debug: debug) }
        else
          spec
        end
      end

      private_class_method def self.resolve_json_pointer(spec, json_pointer, _matched_path, _referencing_file)
        pointer_parts = json_pointer.split('/').reject(&:empty?)
        target = spec
        pointer_parts.each do |part|
          part = part.gsub('~1', '/').gsub('~0', '~')
          target = target[part] if target.is_a?(Hash)
          target = target[part.to_i] if target.is_a?(Array) && part.match?(/^\d+$/)
          return nil unless target
        end
        target
      end

      private_class_method def self.resolve_ref_path(opts = {})
        ref = opts[:ref]
        spec_paths = opts[:spec_paths] ||= []
        referencing_file = opts[:referencing_file] || 'unknown'

        ref = ref.sub('file://', '') if ref.start_with?('file://')
        return ref if ref.start_with?('http://', 'https://')

        normalized_ref = ref.sub(%r{^\./}, '').sub(%r{^/}, '')
        spec_paths.each do |path|
          normalized_path = path.sub(%r{^\./}, '').sub(%r{^/}, '')
          return path if normalized_path == normalized_ref || File.basename(normalized_path) == File.basename(normalized_ref)
        end

        ref
      end

      private_class_method def self.deep_merge(opts = {})
        hash1 = opts[:hash1] || {}
        hash2 = opts[:hash2] || {}

        # hash1.merge(hash2) do |key, old_val, new_val|
        hash1.merge(hash2) do |_key, old_val, new_val|
          # if key.start_with?('x-')
          #   new_val || old_val
          # elsif old_val.is_a?(Hash) && new_val.is_a?(Hash)
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(hash1: old_val, hash2: new_val)
          elsif old_val.is_a?(Array) && new_val.is_a?(Array)
            (old_val + new_val).uniq
          else
            new_val || old_val
          end
        end
      end

      private_class_method def self.extract_refs(opts = {})
        spec = opts[:spec]
        spec_paths = opts[:spec_paths]
        refs = opts[:refs] ||= Set.new
        case spec
        when Hash
          spec.each do |key, value|
            if key == '$ref' && value.is_a?(String)
              ref_path = value.split('#', 2).first
              resolved_path = resolve_ref_path(ref: ref_path, spec_paths: spec_paths, referencing_file: nil)
              refs << resolved_path unless ref_path.empty? || ref_path.start_with?('http://', 'https://')
            end
            extract_refs(spec: value, spec_paths: spec_paths, refs: refs)
          end
        when Array
          spec.each { |item| extract_refs(spec: item, spec_paths: spec_paths, refs: refs) }
        end
        refs
      end

      private_class_method def self.dfs(opts = {})
        node = opts[:node]
        dependencies = opts[:dependencies]
        visited = opts[:visited] ||= Set.new
        temp = opts[:temp] ||= Set.new
        result = opts[:result] ||= []
        path = opts[:path] ||= []

        if temp.include?(node)
          path << node
          cycle_start = path.index(node)
          cycle = path[cycle_start..-1]
          return cycle
        end

        unless visited.include?(node)
          temp.add(node)
          path << node
          dependencies[node]&.each do |dep|
            cycle = dfs(node: dep, dependencies: dependencies, visited: visited, temp: temp, result: result, path: path)
            return cycle if cycle
          end
          visited.add(node)
          temp.delete(node)
          result << node
          path.pop
        end
        nil
      end

      private_class_method def self.topological_sort(opts = {})
        dependencies = opts[:dependencies]
        spec_paths = opts[:spec_paths] || []

        result = []
        visited = Set.new
        temp = Set.new
        path = []

        cycle = nil
        dependencies.each_key do |node|
          next if visited.include?(node)

          cycle = dfs(node: node, dependencies: dependencies, visited: visited, temp: temp, result: result, path: path)
          break if cycle
        end

        [cycle ? spec_paths : result.reverse, cycle]
      end

      private_class_method def self.log(message, opts = {})
        debug = opts[:debug] || false
        warn("[DEBUG] #{message}") if debug
      end

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      public_class_method def self.help
        puts "USAGE:
          openapi_spec = #{self}.generate_spec(
            spec_paths: 'required - array of OpenAPI file paths to merge',
            base_url: 'required - base URL for OpenAPI endpoints (e.g., http://fqdn.com)',
            output_json_path: 'optional - path to save the merged OpenAPI JSON file',
            target_version: 'optional - target OpenAPI version (default: 3.0.3)',
            debug: 'optional - boolean to enable debug logging (default: false)'
          )

          #{self}.authors
        "
      end
    end
  end
end
