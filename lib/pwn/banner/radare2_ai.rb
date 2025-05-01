# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module Radare2AI
      # Supported Method Parameters::
      # PWN::Banner::Radare2AI.get

      public_class_method def self.get
        '
        $ target_bin="/usr/bin/id";
        $ alias r2="setarch $(uname -m) -R r2 -AA -c \"v r2-pwn-layout\""
        $ r2 $target_bin
           -- Log On. Hack In. Go Anywhere. Get Everything.
          [0x7ffff7fe35c0]> aaaa
          INFO: Analyze all flags starting with sym. and entry0 (aa)
          INFO: Analyze imports (af@@@i)
          INFO: Analyze entrypoint (af@ entry0)
          INFO: Analyze symbols (af@@@s)
          INFO: Analyze all functions arguments/locals (afva@@@F)
          INFO: Analyze function calls (aac)
          INFO: Analyze len bytes of instructions for references (aar)
          INFO: Finding and parsing C++ vtables (avrr)
          INFO: Analyzing methods (af @@ method.*)
          INFO: Recovering local variables (afva@@@F)
          INFO: Skipping type matching analysis in debugger mode (aaft)
          INFO: Propagate noreturn information (aanr)
          INFO: Scanning for strings constructed in code (/azs)
          INFO: Finding function preludes (aap)
          INFO: Enable anal.types.constraint for experimental type propagation
          [0x7ffff7fe35c0]> db main
          [0x7ffff7fe35c0]> dc
          INFO: hit breakpoint at: 0x555555556490
          [0x555555556490]> decai -e lang=C++
          [0x555555556490]> decai -e
          decai -e pipeline=
          decai -e model=Radare2:latest
          decai -e deterministic=true
          decai -e debug=false
          decai -e api=ollama
          decai -e lang=C++
          decai -e hlang=English
          decai -e cache=false
          decai -e cmds=pdga
          decai -e prompt=Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change goto into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like string:, Reduce lines of code and fit everything in a single function, removing all dead code.  Most importantly, determine if this code is exploitable.
          decai -e ctxfile=
          decai -e host=http://localhost
          decai -e port=11434
          decai -e maxinputtokens=-1
          [0x555555556490]> decai -d
          // Function to get the effective user ID and group ID
          // Returns the effective user ID and group ID as a string in the format "effective_uid:effective_gid"
          // If an error occurs, returns an empty string

          #include <stdio.h>
          #include <stdlib.h>
          #include <string.h>
          #include <unistd.h>
          #include <errno.h>
          #include <sys/types.h>
          #include <sys/stat.h>

          char* get_effective_ids() {
              gid_t effective_gid;
              uid_t effective_uid;
              
              // Get effective GID
              effective_gid = getegid();
              if (effective_gid == -1) {
                  perror("getegid");
                  return "";
              }

              // Get effective UID
              effective_uid = geteuid();
              if (effective_uid == -1) {
                  perror("geteuid");
                  return "";
              }

              // Format and return the result
              char result[32];
              snprintf(result, sizeof(result), "effective_uid:%d effective_gid:%d", (int)effective_uid, (int)effective_gid);
              return strdup(result);
          }
          ```

          This code defines a new function `get_effective_ids()` that uses the standard library functions `geteuid()` and `getegid()` to get the effective user ID and group ID, respectively. It then formats the result as a string in the format "effective_uid:effective_gid" and returns it using `strdup()` to allocate memory for the result. If an error occurs while getting the effective IDs, the function returns an empty string.
        '.yellow
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
