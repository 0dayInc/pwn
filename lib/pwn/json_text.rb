# frozen_string_literal: true

# Retag or scrub strings before the JSON generator sees them.
# json 2.21 warns when valid UTF-8 is still tagged BINARY, and raises
# JSON::GeneratorError on a malformed sequence. Both show up in the session pane.
module PWN
  # Retag or scrub strings before JSON.generate, JSON.dump, or to_json.
  module JSONText
    module_function

    def prepare(value, depth = 0)
      case value
      when String
        utf = value.dup.force_encoding(Encoding::UTF_8)
        utf.valid_encoding? ? utf : utf.scrub
      when Hash
        return value if depth >= 100

        value.each_with_object({}) do |(key, item), out|
          out[key.is_a?(String) ? prepare(key, depth + 1) : key] = prepare(item, depth + 1)
        end
      when Array
        return value if depth >= 100

        value.map { |item| prepare(item, depth + 1) }
      else
        value
      end
    end

    # Covers JSON.generate, JSON.dump, and to_json. All three enter here.
    module Generate
      def generate(obj, *rest)
        super(PWN::JSONText.prepare(obj), *rest)
      end

      def _generate_no_fallback(obj, *rest)
        super(PWN::JSONText.prepare(obj), *rest)
      end
    end
  end
end

JSON::State.singleton_class.prepend(PWN::JSONText::Generate)
JSON::State.prepend(PWN::JSONText::Generate)
