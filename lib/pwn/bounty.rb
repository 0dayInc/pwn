# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads Bounty modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Bounty
    autoload :LifecycleAuthzReplay, 'pwn/bounty/lifecycle_authz_replay'

    # Display a List of Every PWN::Bounty Module

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      constants.sort
    end
  end
end
