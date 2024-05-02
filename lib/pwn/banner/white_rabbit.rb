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
             _       _
            / \     / \
           {   }   {   }
           {   {   }   }
            \   \ /   /
             \   Y   /
             .-"`"`"-.
           ,`         `.
          /             \
         /               \
        {     ."";,       }
        {  /";`.`,;       }
         \{  ;`,``;.     /
          {  }`""`  }   /}
          {  }      {  //
          {||}      {  /
          `"`       pwn
        '.white
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
          #{self}.get

          #{self}.authors
        "
      end
    end
  end
end
