# frozen_string_literal: true

# Retag or scrub strings before the JSON generator sees them.
module PWN
  # json 2.21 warns when valid UTF-8 is still tagged BINARY, and raises
  # JSON::GeneratorError on a malformed sequence. Both show up in the session pane.
  module JSONText
    # Supported Method Parameters::
    # safe = PWN::JSONText.prepare(
    #   value: 'required - string, hash, or array that may contain binary-tagged text',
    #   depth: 'optional - nesting already walked; containers stop at 100'
    # )

    public_class_method def self.prepare(opts = {})
      value = opts[:value]
      depth = opts[:depth].to_i
      case value
      when String
        utf = value.dup.force_encoding(Encoding::UTF_8)
        utf.valid_encoding? ? utf : utf.scrub
      when Hash
        return value if depth >= 100

        value.each_with_object({}) do |(key, item), out|
          out[key.is_a?(String) ? prepare(value: key, depth: depth + 1) : key] = prepare(value: item, depth: depth + 1)
        end
      when Array
        return value if depth >= 100

        value.map { |item| prepare(value: item, depth: depth + 1) }
      else
        value
      end
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module.

    public_class_method def self.help
      puts "USAGE:
        # Retag valid UTF-8 that is still tagged binary, or scrub an illegal sequence.
        #{self}.prepare(
          value: 'required - string, hash, or array that may contain binary-tagged text',
          depth: 'optional - nesting already walked; containers stop at 100'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end

# json 2.21 warns inside JSON.generate before State.generate. json 2.18 warns
# inside the C to_json methods. Retag at both doors.
class << JSON
  %i[generate fast_generate pretty_generate dump].each do |name|
    alias_method :"#{name}_without_json_text", name
    define_method(name) do |obj, *rest|
      public_send(:"#{name}_without_json_text", PWN::JSONText.prepare(value: obj), *rest)
    end
  end
end

if defined?(JSON::Ext::Generator::GeneratorMethods)
  JSON::Ext::Generator::GeneratorMethods.constants.each do |kind|
    mod = JSON::Ext::Generator::GeneratorMethods.const_get(kind)
    next unless mod.is_a?(Module) && mod.method_defined?(:to_json)

    mod.class_eval do
      alias_method :to_json_without_json_text, :to_json unless method_defined?(:to_json_without_json_text)
      define_method(:to_json) do |*rest|
        prepared = PWN::JSONText.prepare(value: self)
        mod.instance_method(:to_json_without_json_text).bind_call(prepared, *rest)
      end
    end
  end
end
