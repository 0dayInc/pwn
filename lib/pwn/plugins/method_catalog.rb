# frozen_string_literal: true

require 'json'
require 'ripper'
require 'yard'

module PWN
  module Plugins
    # JSON-schema descriptors for public PWN::Plugins methods, generated from
    # YARD / Supported Method Parameters docs. pwn_eval validates kwargs first.
    module MethodCatalog
      SIDE_EFFECTS = %w[read_only active_scan exploit destructive].freeze

      public_class_method def self.required_bins
        []
      end

      # Build a JSON-schema descriptor for one public plugin method.
      public_class_method def self.schema(opts = {})
        mod = plugin_const(opts)
        name = (opts[:method] || opts[:name]).to_s
        raise 'ERROR: method is required' if name.empty?

        cache_key = "#{mod}##{name}"
        @schema_cache ||= {}
        return @schema_cache[cache_key] if @schema_cache[cache_key]

        keys = allowed_keys(mod: mod, method: name)
        props = keys.to_h { |key, hint| [key, property_schema(key: key, hint: hint)] }
        @schema_cache[cache_key] = {
          name: "#{mod}.#{name}",
          description: purpose_line(mod: mod, method: name),
          side_effect: classify_side_effect(mod: mod, method: name),
          parameters: {
            type: 'object',
            properties: props,
            additionalProperties: false
          }
        }
      end

      # Validate literal kwargs on PWN::Plugins calls; nil means the payload may eval.
      public_class_method def self.guard_eval(opts = {})
        code = opts[:code].to_s
        extract_calls(code: code).each do |call|
          descriptor = schema(mod: call[:mod], method: call[:method])
          allowed = descriptor[:parameters][:properties].keys.map(&:to_s)
          unknown = call[:keys].map(&:to_s) - allowed
          next if unknown.empty?

          return {
            error: "unknown keyword: #{unknown.join(', ')}",
            schema: descriptor,
            method: descriptor[:name]
          }
        end
        nil
      rescue SyntaxError
        nil
      end

      # List descriptors for every public PWN::Plugins class method (lazy per module).
      public_class_method def self.descriptors(opts = {})
        mods = Array(opts[:modules] || plugin_modules)
        mods.flat_map do |mod|
          public_methods_for(mod: mod).map { |name| schema(mod: mod, method: name) }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Build a JSON-schema descriptor for one public plugin method.
          #{self}.schema(
            mod: 'optional - PWN::Plugins::Name or short Name',
            module: 'optional - alias for mod',
            method: 'required - public class method name',
            name: 'optional - alias for method'
          )

          # Validate literal kwargs on PWN::Plugins calls; nil means the payload may eval.
          #{self}.guard_eval(
            code: 'required - Ruby source that may call PWN::Plugins methods'
          )

          # List descriptors for every public PWN::Plugins class method (lazy per module).
          #{self}.descriptors(
            modules: 'optional - Array of PWN::Plugins constants to catalog'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.plugin_const(opts = {})
        raw = (opts[:mod] || opts[:module] || opts[:const]).to_s
        raw = "PWN::Plugins::#{raw}" unless raw.include?('::')
        raise 'ERROR: module is required' if raw.empty? || raw == 'PWN::Plugins::'
        raise 'ERROR: only PWN::Plugins methods are catalogued' unless raw.start_with?('PWN::Plugins::')

        raw
      end

      private_class_method def self.plugin_modules(opts = {})
        _n = opts[:n]
        PWN::Plugins.constants.sort.map { |name| "PWN::Plugins::#{name}" }.select do |mod|
          Object.const_get(mod).is_a?(Module)
        rescue StandardError
          false
        end
      end

      private_class_method def self.public_methods_for(opts = {})
        klass = Object.const_get(opts[:mod].to_s)
        klass.singleton_methods(false).map(&:to_s).reject { |name| %w[allocate new].include?(name) }.sort
      rescue StandardError
        []
      end

      private_class_method def self.classify_side_effect(opts = {})
        blob = "#{opts[:mod]} #{opts[:method]} #{purpose_line(opts)}".downcase
        return 'destructive' if blob.match?(/rm_rf|unlink|delete|kill|wipe|drop|destroy|format|truncate/)
        return 'exploit' if blob.match?(/exploit|overflow|shellcode|ret2|rce|payload/)
        return 'active_scan' if blob.match?(/scan|fuzz|brute|attack|nuclei|nmap|crawl|inject/)

        'read_only'
      end

      private_class_method def self.property_schema(opts = {})
        hint = opts[:hint].to_s.downcase
        type = case hint
               when /bool/
                 'boolean'
               when /array/
                 'array'
               when /int|number|float/
                 'number'
               else
                 'string'
               end
        { type: type, description: opts[:hint].to_s }
      end

      private_class_method def self.allowed_keys(opts = {})
        mod = opts[:mod].to_s
        name = opts[:method].to_s
        hints = {}
        yard_options(text: comment_block(mod: mod, method: name)).each { |key, hint| hints[key] = hint }
        help_options(mod: mod, method: name).each { |key, hint| hints[key] = hint }
        body_keys(mod: mod, method: name).each { |key| hints[key] ||= key }
        hints
      end

      private_class_method def self.yard_options(opts = {})
        require 'yard'
        doc = YARD::Docstring.new(opts[:text].to_s)
        found = {}
        (doc.tags('option') + doc.tags('param')).each do |tag|
          key = (tag.pair&.name || tag.name).to_s.delete_prefix(':')
          next if key.empty? || key == 'opts'

          found[key] = [tag.types&.join(','), tag.text].compact.join(' ').strip
        end
        opts[:text].to_s.scan(/(\w+):\s*['"]((?:required|optional)[^'"]*)['"]/i) { |key, hint| found[key] = hint }
        found
      rescue StandardError
        {}
      end

      private_class_method def self.comment_block(opts = {})
        klass = Object.const_get(opts[:mod].to_s)
        path, line = klass.method(opts[:method].to_sym).source_location
        return '' unless path && line

        lines = File.readlines(path)
        buf = []
        (line - 2).downto(0) do |idx|
          text = lines[idx]
          break unless text&.match?(/^\s*#/)

          buf.unshift(text.sub(/^\s*#\s?/, ''))
        end
        buf.join
      rescue StandardError
        ''
      end

      private_class_method def self.help_options(opts = {})
        klass = Object.const_get(opts[:mod].to_s)
        path, = klass.method(:help).source_location
        return {} unless path && File.file?(path)

        text = File.read(path)
        name = Regexp.escape(opts[:method].to_s)
        chunk = text[/#\{self\}\.#{name}\((.*?)\)/m, 1]
        return {} unless chunk

        chunk.scan(/(\w+):\s*['"]((?:required|optional)[^'"]*)['"]/i).to_h
      rescue StandardError
        {}
      end

      private_class_method def self.body_keys(opts = {})
        klass = Object.const_get(opts[:mod].to_s)
        path, line = klass.method(opts[:method].to_sym).source_location
        return [] unless path && line && File.file?(path)

        lines = File.readlines(path)
        indent = lines[line - 1][/^\s*/]
        body = []
        ((line - 1)...lines.length).each do |idx|
          body << lines[idx]
          break if idx > (line - 1) && lines[idx].match?(/^#{Regexp.escape(indent)}end\b/)
        end
        body.join.scan(/opts\[\s*:([A-Za-z_]\w*)\s*\]/).flatten.uniq
      rescue StandardError
        []
      end

      private_class_method def self.purpose_line(opts = {})
        comment_block(opts).to_s.lines.map(&:strip).reject(&:empty?).first.to_s
      end

      private_class_method def self.extract_calls(opts = {})
        sexp = Ripper.sexp(opts[:code].to_s)
        return [] unless sexp

        found = []
        walk_sexp(node: sexp, found: found)
        found.select { |row| row[:mod].to_s.start_with?('PWN::Plugins::') && !row[:keys].nil? }
      end

      private_class_method def self.walk_sexp(opts = {})
        node = opts[:node]
        found = opts[:found]
        return unless node.is_a?(Array)

        if node[0] == :method_add_arg && node[1].is_a?(Array) && node[1][0] == :call
          rec = call_record(node: node[1], args: node[2])
          found << rec if rec
        elsif %i[call command_call].include?(node[0])
          rec = call_record(node: node)
          found << rec if rec
        end
        node.each { |child| walk_sexp(node: child, found: found) if child.is_a?(Array) }
      end

      private_class_method def self.call_record(opts = {})
        node = opts[:node]
        recv = node[1]
        name_node = node[3]
        args_node = opts[:args] || node[4]
        ident = name_node.is_a?(Array) && name_node[0] == :@ident ? name_node[1] : nil
        mod = const_path(node: recv)
        return nil if ident.nil? || mod.nil?

        keys = kwarg_keys(node: args_node)
        return nil if keys.nil?

        { mod: mod, method: ident, keys: keys }
      end

      private_class_method def self.const_path(opts = {})
        node = opts[:node]
        return nil unless node.is_a?(Array)

        case node[0]
        when :@const
          node[1]
        when :var_ref, :top_const_ref
          const_path(node: node[1])
        when :const_path_ref, :const_path_field
          left = const_path(node: node[1])
          right = const_path(node: node[2])
          [left, right].compact.join('::')
        end
      end

      private_class_method def self.kwarg_keys(opts = {})
        node = opts[:node]
        return [] if node.nil?
        return nil unless node.is_a?(Array)

        return kwarg_keys(node: node[1]) if node[0] == :arg_paren

        hash = find_assoc_hash(node: node)
        return nil if hash.nil? && ident_arg?(node: node)
        return [] if hash.nil?

        hash.each_with_object([]) do |assoc, keys|
          next unless assoc.is_a?(Array) && assoc[0] == :assoc_new

          label = assoc[1]
          keys << label[1].to_s.delete_suffix(':') if label.is_a?(Array) && label[0] == :@label
        end
      end

      private_class_method def self.find_assoc_hash(opts = {})
        node = opts[:node]
        return nil unless node.is_a?(Array)
        return node[1] if node[0] == :bare_assoc_hash

        node.each do |child|
          next unless child.is_a?(Array)

          found = find_assoc_hash(node: child)
          return found if found
        end
        nil
      end

      private_class_method def self.ident_arg?(opts = {})
        node = opts[:node]
        return false unless node.is_a?(Array)

        node.flatten.include?(:@ident) && !node.flatten.include?(:@label)
      end
    end
  end
end
