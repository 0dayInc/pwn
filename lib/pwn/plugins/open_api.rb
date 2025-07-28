# frozen_string_literal: true

require 'yaml'
require 'json'
require 'uri'
require 'fileutils'

module PWN
  module Plugins
    # Plugins to interact with OpenAPI specifications,
    # while automatically resolving schema dependencies.
    module OpenAPI
      # Supported Method Parameters:
      # openapi_spec = PWN::Plugins::OpenAPI.import_spec(
      #   spec_paths: 'required - array of OpenAPI file paths to merge into a the output_json_path',
      #   base_url: 'required - base URL for OpenAPI endpoints (e.g., http://fqdn.com)',
      #   output_json_path: 'optional - path to save the merged OpenAPI JSON file (e.g., /path/to/merged_openapi.json)'
      # )
      def self.import_spec(opts = {})
        spec_paths = opts[:spec_paths] ||= []
        raise ArgumentError, 'spec_paths must be a non-empty array' if spec_paths.empty?

        base_url = opts[:base_url]
        raise ArgumentError, 'base_url is required' if base_url.nil? || base_url.empty?

        # Normalize base_url to ensure it's an absolute URL
        normalized_base_url = normalize_url(base_url)
        output_json_path = opts[:output_json_path]

        begin
          # Load and parse all OpenAPI files
          specs = {}
          spec_paths.each do |path|
            raise Errno::ENOENT, "OpenAPI file not found: #{path}" unless File.exist?(path)

            begin
              case File.extname(path).downcase
              when '.yaml', '.yml'
                specs[path] = YAML.load_file(path, permitted_classes: [Symbol, Date, Time])
              when '.json'
                specs[path] = JSON.parse(File.read(path))
              else
                raise "Unsupported file type: #{path} - only .yaml, .yml, and .json files"
              end
            rescue YAML::SyntaxError, JSON::ParserError => e
              raise "Error parsing OpenAPI file #{path}: #{e.message}"
            end
          end

          # Determine dependencies based on $ref
          dependencies = {}
          specs.each do |path, spec|
            dependencies[path] = []
            refs = extract_refs(spec: spec, spec_paths: spec_paths)
            refs.each do |ref|
              dep_path = resolve_ref_path(ref, spec_paths, referencing_file: path)
              dependencies[path] << dep_path if specs.key?(dep_path) && dep_path != path
            end
          end

          # Sort files by dependencies (topological sort with cycle detection)
          ordered_paths, cycle_info = topological_sort(dependencies: dependencies)
          if cycle_info
            puts "Warning: Cyclic dependencies detected: #{cycle_info.join(' -> ')}. Processing files in provided order."
            ordered_paths = spec_paths
          end

          # Merge OpenAPI specs into a single specification
          merged_spec = {
            'openapi' => '3.0.3', # Default to OpenAPI 3.0.3
            'info' => {},
            'servers' => [{ 'url' => normalized_base_url }],
            'paths' => {},
            'components' => {},
            'tags' => [],
            'security' => []
          }

          ordered_paths.each do |path|
            spec = specs[path]
            unless spec.is_a?(Hash)
              puts "Skipping #{path}: Invalid OpenAPI specification"
              next
            end

            # Resolve external $ref references
            resolved_spec = resolve_refs(spec: spec, specs: specs, spec_paths: spec_paths, referencing_file: path)

            # Validate and fix path parameters
            resolved_spec['paths'] = validate_path_parameters(resolved_spec['paths'], path) if resolved_spec['paths'].is_a?(Hash)

            # Merge 'openapi' version
            merged_spec['openapi'] = resolved_spec['openapi'] if resolved_spec['openapi'] && (resolved_spec['openapi'] > merged_spec['openapi'])

            # Merge 'info'
            merged_spec['info'] = deep_merge(merged_spec['info'], resolved_spec['info']) if resolved_spec['info'].is_a?(Hash)

            # Merge 'servers'
            if resolved_spec['servers']
              servers = resolved_spec['servers'].is_a?(Array) ? resolved_spec['servers'] : [resolved_spec['servers']]
              servers.each do |server|
                server_url = server.is_a?(Hash) ? server['url'] : server
                next unless server_url.is_a?(String)

                absolute_url = normalize_url(server_url, base_url: normalized_base_url)
                server_obj = server.is_a?(Hash) ? server.merge('url' => absolute_url) : { 'url' => absolute_url }
                merged_spec['servers'] << server_obj unless merged_spec['servers'].any? { |s| s['url'] == absolute_url }
              end
            end

            # Merge 'paths'
            if resolved_spec['paths'].is_a?(Hash)
              merged_spec['paths'].merge!(resolved_spec['paths']) do |api_endpoint, _existing, new|
                puts "Warning: Path '#{api_endpoint}' in #{path} conflicts with existing path. Overwriting."
                new
              end
            end

            # Merge 'components'
            merged_spec['components'] = deep_merge(merged_spec['components'], resolved_spec['components']) if resolved_spec['components'].is_a?(Hash)

            # Merge 'tags'
            next unless resolved_spec['tags'].is_a?(Array)

            resolved_spec['tags'].each do |tag|
              merged_spec['tags'] << tag unless merged_spec['tags'].include?(tag)
            end

            # Merge 'security'
            next unless resolved_spec['security'].is_a?(Array)

            resolved_spec['security'].each do |security|
              merged_spec['security'] << security unless merged_spec['security'].include?(security)
            end
          end

          # Ensure at least one valid server URL
          if merged_spec['servers'].empty?
            merged_spec['servers'] = [{ 'url' => normalized_base_url }]
            puts "Warning: No valid server URLs found in specs. Using base_url: #{normalized_base_url}"
          end

          # Write merged spec to JSON file if provided
          if output_json_path
            FileUtils.mkdir_p(File.dirname(output_json_path))
            File.write(output_json_path, JSON.pretty_generate(merged_spec))
            puts "Merged OpenAPI specification written to: #{output_json_path}"
          end

          { individual_specs: specs, merged_spec: merged_spec }
        rescue Errno::ENOENT => e
          raise "Error accessing file: #{e.message}"
        rescue StandardError => e
          raise "Unexpected error: #{e.message}"
        end
      end

      # Validates and fixes path parameters in paths object
      private_class_method def self.validate_path_parameters(paths, file_path)
        paths.transform_values do |path_item|
          next path_item unless path_item.is_a?(Hash)

          # Extract path parameters from the endpoint
          path_params = path_item['parameters']&.select { |p| p['in'] == 'path' }&.map { |p| p['name'] } || []
          endpoint = path_item['$ref'] || path_item.keys.join('/')
          path_item.each_value do |operation|
            next unless operation.is_a?(Hash)

            # Find path parameters in the endpoint URL
            required_params = endpoint.scan(/\{([^}]+)\}/).flatten
            operation_params = operation['parameters']&.select { |p| p['in'] == 'path' }&.map { |p| p['name'] } || []

            # Check for missing path parameters
            next if (missing_params = required_params - (path_params + operation_params)).empty?

            puts "Warning: In #{file_path}, path '#{endpoint}' has undeclared path parameters: #{missing_params.join(', ')}. Adding default definitions."
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
          path_item
        end
      end

      # Normalizes URLs to absolute form
      private_class_method def self.normalize_url(url, base_url: nil)
        return url if url.nil? || url.empty?

        begin
          uri = URI.parse(url)
          return uri.to_s if uri.absolute? && uri.scheme && uri.host

          # If no base_url provided, use a default
          base_uri = if base_url && !base_url.empty?
                       URI.parse(normalize_url(base_url))
                     else
                       URI.parse('http://localhost')
                     end

          # Handle relative URLs
          if url.start_with?('/')
            # Absolute path relative to base_url
            uri = base_uri.dup
            uri.path = url
            uri.query = nil
            uri.fragment = nil
          else
            # Relative path
            uri = base_uri.merge(url)
          end
          uri.to_s
        rescue URI::InvalidURIError => e
          puts "Warning: Invalid URL '#{url}' - using base_url or default: #{base_url || 'http://localhost'}"
          base_url || 'http://localhost'
        end
      end

      # Resolves $ref references using spec_paths
      private_class_method def self.resolve_refs(spec:, specs:, spec_paths:, referencing_file:)
        case spec
        when Hash
          resolved = {}
          spec.each do |key, value|
            next resolved[key] = resolve_refs(spec: value, specs: specs, spec_paths: spec_paths, referencing_file: referencing_file) unless key == '$ref' && value.is_a?(String)

            ref_path, json_pointer = value.split('#', 2)
            json_pointer ||= ''
            matched_path = resolve_ref_path(ref_path, spec_paths, referencing_file: referencing_file)

            unless specs.key?(matched_path)
              puts "Warning: Unable to load RELATIVE ref: #{ref_path} from #{referencing_file} (no match in spec_paths)"
              begin
                # Attempt to load the file if it exists
                unless File.exist?(ref_path)
                  puts "Warning: File #{ref_path} does not exist on filesystem"
                  return value
                end
                case File.extname(ref_path).downcase
                when '.yaml', '.yml'
                  specs[ref_path] = YAML.load_file(ref_path, permitted_classes: [Symbol, Date, Time])
                  spec_paths << ref_path unless spec_paths.include?(ref_path)
                when '.json'
                  specs[ref_path] = JSON.parse(File.read(ref_path))
                  spec_paths << ref_path unless spec_paths.include?(ref_path)
                else
                  puts "Warning: Unsupported file type for #{ref_path}"
                  return value
                end
              rescue StandardError => e
                puts "Warning: Failed to load #{ref_path}: #{e.message}"
                return value
              end
            end

            ref_spec = specs[matched_path]
            resolved[key] = if json_pointer.empty?
                              resolve_refs(spec: ref_spec, specs: specs, spec_paths: spec_paths, referencing_file: matched_path)
                            else
                              pointer_parts = json_pointer.split('/').reject(&:empty?)
                              target = ref_spec
                              pointer_parts.each do |part|
                                target = target[part] if target.is_a?(Hash) || target.is_a?(Array)
                                break unless target
                              end
                              if target
                                resolve_refs(spec: target, specs: specs, spec_paths: spec_paths, referencing_file: matched_path)
                              else
                                puts "Warning: Invalid JSON pointer #{json_pointer} in #{matched_path} from #{referencing_file}"
                                value
                              end
                            end
          end
          resolved
        when Array
          spec.map { |item| resolve_refs(spec: item, specs: specs, spec_paths: spec_paths, referencing_file: referencing_file) }
        else
          spec
        end
      end

      # Resolves a $ref path by matching against spec_paths
      private_class_method def self.resolve_ref_path(ref, spec_paths, referencing_file:)
        # Remove 'file://' prefix if present
        ref = ref.sub('file://', '') if ref.start_with?('file://')

        # If ref is an HTTP/HTTPS URL, return it unchanged
        return ref if ref.start_with?('http://', 'https://')

        # Normalize ref by removing leading './' or '/' for matching
        normalized_ref = ref.sub(%r{^\./}, '').sub(%r{^/}, '')

        # Check if ref matches any path in spec_paths
        spec_paths.each do |path|
          normalized_path = path.sub(%r{^\./}, '').sub(%r{^/}, '')
          return path if normalized_path == normalized_ref || File.basename(normalized_path) == File.basename(normalized_ref)
        end

        # If no match, return the original ref to allow fallback loading
        puts "Warning: Could not resolve $ref '#{ref}' from #{referencing_file} to any spec_paths entry"
        ref
      end

      # Deep merges two hashes
      private_class_method def self.deep_merge(hash1, hash2)
        hash1.merge(hash2) do |_key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(old_val, new_val)
          elsif old_val.is_a?(Array) && new_val.is_a?(Array)
            (old_val + new_val).uniq
          else
            new_val || old_val
          end
        end
      end

      # Extracts $ref references and matches against spec_paths
      private_class_method def self.extract_refs(opts = {})
        spec = opts[:spec]
        spec_paths = opts[:spec_paths]
        refs = opts[:refs] ||= Set.new
        case spec
        when Hash
          spec.each do |key, value|
            if key == '$ref' && value.is_a?(String)
              ref_path = value.split('#', 2).first
              resolved_path = resolve_ref_path(ref_path, spec_paths, referencing_file: nil)
              refs << resolved_path unless ref_path.start_with?('http://', 'https://')
            end
            extract_refs(spec: value, spec_paths: spec_paths, refs: refs)
          end
        when Array
          spec.each { |item| extract_refs(spec: item, spec_paths: spec_paths, refs: refs) }
        end
        refs
      end

      # Depth-first search for topological sort with cycle detection
      # rubocop:disable Metrics/ParameterLists
      private_class_method def self.dfs(node, dependencies, visited, temp, result, path)
        if temp.include?(node)
          path << node
          cycle_start = path.index(node)
          cycle = path[cycle_start..-1]
          return cycle # Return the cycle path
        end

        unless visited.include?(node)
          temp.add(node)
          path << node
          dependencies[node]&.each do |dep|
            cycle = dfs(dep, dependencies, visited, temp, result, path)
            return cycle if cycle # Propagate cycle if found
          end
          visited.add(node)
          temp.delete(node)
          result << node
          path.pop
        end
        nil # No cycle found
      end
      # rubocop:enable Metrics/ParameterLists

      # Topological sort for dependency resolution
      private_class_method def self.topological_sort(dependencies:)
        result = []
        visited = Set.new
        temp = Set.new
        path = []

        cycle = nil
        dependencies.each_key do |node|
          next if visited.include?(node)

          cycle = dfs(node, dependencies, visited, temp, result, path)
          break if cycle
        end

        if cycle
          [result.reverse, cycle]
        else
          [result.reverse, nil]
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      public_class_method def self.help
        puts "USAGE:
          openapi_spec = #{self}.import_spec(
            spec_paths: 'required - array of OpenAPI file paths to merge into the output_json_path',
            base_url: 'required - base URL to use for OpenAPI endpoints (e.g. http://fqdn.com)',
            output_json_path: 'optional - path to save the merged OpenAPI JSON file (e.g., /path/to/merged_openapi.json)'
          )

          #{self}.authors
        "
      end
    end
  end
end
