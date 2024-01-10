# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module WhiteRabbit
      # Supported Method Parameters::
      # PWN::Banner::WhiteRabbit.get

      public_class_method def self.get
        '
         / \
        / _ \
       | / \ |
       ||   || _______
       ||   || |\     \
       ||   || ||\     \
       ||   || || \    |
       ||   || ||  \__/
       ||   || ||   ||
        \\_/ \_/ \_//
       /             \
      /   /      ^    \
      |    X     *    |
      |  __  ___  __  |
     /       \_/       \
    /  ----   |   -.    \
    |     \__/|\__/ \   |
    \       |_|_|       /
     \_____       _____/
           \_____/
          >>>PWN<<<
         |__/ v \__|
        '.white
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
          #{self}.get

          #{self}.authors
        "
      end
    end
  end
end
