# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for converting Speech to Text,
    # Text to Speech, and Realtime Voice Mutation
    module Voice
      # Supported Method Parameters::
      # response = PWN::Plugins::Voice.mutate(
      #   sox_path: 'optional - path to sox application (defaults to /usr/bin/sox)',
      # )

      public_class_method def self.mutate(opts = {})
        sox_path = opts[:sox_path]
        sox_path ||= '/usr/bin/sox'

        raise "SOX Not Found: #{sox_path}" unless File.exist?(sox_path)

        puts 'Press CTRL+C to Exit....'
        system(
          sox_path,
          '-d',
          '-d',
          'pitch',
          '-700',
          'contrast',
          '100',
          'echo',
          '0.8',
          '0.88',
          '6',
          '0.4'
        )
      rescue Interrupt
        puts "\nGoodbye."
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::Voice.speech_to_text(
      #   audio_file_path: 'required - path to audio file',
      #   whisper_path: 'optional - path to OpenAI whisper application (defaults to /usr/local/bin/whisper)',
      #   model: 'optional - transcribe model to use (defaults to tiny)',
      #   output_dir: 'optional - directory to output results (defaults to .)'
      # )

      public_class_method def self.speech_to_text(opts = {})
        audio_file_path = opts[:audio_file_path]
        whisper_path = opts[:whisper_path]
        whisper_path ||= '/usr/local/bin/whisper'
        model = opts[:model]
        model ||= 'tiny'
        output_dir = opts[:output_dir]
        output_dir ||= '.'

        raise "Speech-to-Text Engine Not Found: #{whisper_path}" unless File.exist?(whisper_path)

        system(
          whisper_path,
          audio_file_path,
          '--model',
          model,
          '--output_dir',
          output_dir
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Voice.text_to_speech(
      #   text_path: 'required - path to text file to speak',
      #   festival_path: 'optional - path to festival app (defaults to /usr/bin/festival)',
      # )

      public_class_method def self.text_to_speech(opts = {})
        text_path = opts[:text_path]
        festival_path = opts[:festival_path]
        festival_path ||= '/usr/bin/festival'

        raise "Festival Not Found: #{festival_path}" unless File.exist?(festival_path)

        raise "Text File Not Found: #{text_path}" unless File.exist?(text_path)

        system(
          festival_path,
          '--tts',
          text_path
        )
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
           #{self}.mutate(
             sox_path: 'optional - path to sox application (defaults to /usr/bin/sox)',
          )

          response = #{self}.speech_to_text(
            audio_file_path: 'required - path to audio file',
            whisper_path: 'optional - path to OpenAI whisper application (defaults to /usr/local/bin/whisper)',
            model: 'optional - transcribe model to use (defaults to tiny)',
            output_dir: 'optional - directory to output results (defaults to .)'
          )

          #{self}.text_to_speech(
            text_path: 'required - path to text file to speak',
            festival_path: 'optional - path to festival app (defaults to /usr/bin/festival)',
          )

          #{self}.authors
        "
      end
    end
  end
end
