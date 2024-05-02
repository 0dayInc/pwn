# frozen_string_literal: true

require 'json'
require 'pty'

module PWN
  module Plugins
    # This plugin is used for converting Speech to Text,
    # Text to Speech, and Realtime Voice Mutation
    module Voice
      # Supported Method Parameters::
      # response = PWN::Plugins::Voice.mutate(
      #   sox_path: 'optional - path to sox application (defaults to /usr/bin/sox)',
      #   pitch: 'optional - integer to alter voice input (defaults to -300)'
      # )

      public_class_method def self.mutate(opts = {})
        sox_path = opts[:sox_path]
        sox_path ||= '/usr/bin/sox'
        pitch = opts[:pitch].to_i
        pitch = -300 if pitch.zero?

        raise "SOX Not Found: #{sox_path}" unless File.exist?(sox_path)

        puts 'Press CTRL+C to Exit....'
        system(
          sox_path,
          '--default-device',
          '--default-device',
          '--no-show-progress',
          'pitch',
          '-q',
          pitch.to_s,
          'contrast',
          '63'
        )

        puts "\nGoodbye."
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
      rescue Interrupt
        puts "\nGoodbye."
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Voice.text_to_speech(
      #   text_path: 'required - path to text file to speak',
      #   festival_path: 'optional - path to festival (defaults to /usr/bin/festival)',
      #   voice: 'optional - voice to use (defaults to cmu_us_slt_arctic_hts)',
      # )

      public_class_method def self.text_to_speech(opts = {})
        text_path = opts[:text_path]
        festival_path = opts[:festival_path]
        festival_path ||= '/usr/bin/festival'
        voice = opts[:voice]
        voice ||= 'cmu_us_slt_arctic_hts'

        raise "Festival Not Found: #{festival_path}" unless File.exist?(festival_path)

        raise "Text File Not Found: #{text_path}" unless File.exist?(text_path)

        text_to_say = File.read(text_path).delete('"')

        system(
          festival_path,
          '--batch',
          "(voice_#{voice})",
          "(SayText \"#{text_to_say}\")"
        )
      rescue Interrupt
        puts "\nGoodbye."
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.mutate(
            sox_path: 'optional - path to sox application (defaults to /usr/bin/sox)',
            pitch: 'optional - integer to alter voice input (defaults to -300)'
          )

          response = #{self}.speech_to_text(
            audio_file_path: 'required - path to audio file',
            whisper_path: 'optional - path to OpenAI whisper application (defaults to /usr/local/bin/whisper)',
            model: 'optional - transcribe model to use (defaults to tiny)',
            output_dir: 'optional - directory to output results (defaults to .)'
          )

          #{self}.text_to_speech(
            text_path: 'required - path to text file to speak',
            festival_path: 'optional - path to festival (defaults to /usr/bin/festival)',
            voice: 'optional - voice to use (defaults to cmu_us_slt_arctic_hts)',
          )

          #{self}.authors
        "
      end
    end
  end
end
