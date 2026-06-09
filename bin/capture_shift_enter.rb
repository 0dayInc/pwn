#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone capture script to discover the exact byte sequence
# your terminal + tmux sends for SHIFT+ENTER.
#
# Run this in the *exact same terminal environment* you use for pwn-ai:
#   bash --login -c 'source /etc/profile.d/rvm.sh; cd /opt/pwn; rvm use .; ruby /tmp/capture_shift_enter.rb'
#
# Then press SHIFT+ENTER when prompted.
# Paste the captured output back here so we can add the missing sequence
# to the shift_enter_seqs list in lib/pwn/plugins/repl.rb .
#
# This must be run with the same TERM, tmux session (if any), and terminal
# emulator (e.g. terminator) as your pwn-ai usage.
# Recommended: set TERM=xterm-256color, and have in ~/.tmux.conf:
#   set -g extended-keys on
#   set -g xterm-keys on
# Then restart tmux completely.

require 'io/console'
require 'timeout'

def capture_sequence(timeout_sec = 10)
  seq = []
  $stdin.raw do |io|
    print "Press SHIFT+ENTER now (you have #{timeout_sec}s)... "
    $stdout.flush

    begin
      Timeout.timeout(timeout_sec) do
        # Read first byte
        first = io.getbyte
        seq << first if first

        # If ESC (27), read the rest of the CSI sequence with short inter-byte timeout
        if first == 27
          loop do
            begin
              Timeout.timeout(0.15) do
                b = io.getbyte
                seq << b if b
              end
            rescue Timeout::Error
              break
            end
            # Safety: don't read forever
            break if seq.size > 20
          end
        else
          # For non-ESC, try to read any immediate followers (rare for enter)
          begin
            Timeout.timeout(0.1) do
              b = io.getbyte
              seq << b if b
            end
          rescue Timeout::Error
            # normal
          end
        end
      end
    rescue Timeout::Error
      puts "\n[timeout]"
    end
  end
  seq
rescue StandardError => e
  puts "\nError during capture: #{e}"
  seq
ensure
  # Always restore cooked mode
  begin
    $stdin.cooked!
  rescue StandardError
    # best-effort restore only; ignore errors if terminal is already in cooked mode or other transient issue
  end
end

puts <<~BANNER
  === SHIFT+ENTER Sequence Capture for pwn-ai ===
  This will capture the raw bytes sent by your terminal when you press SHIFT+ENTER.
  Make sure you are in the same tmux/terminator/TERM setup you use for `pwn-ai`.
  The capture will start after the prompt.
BANNER

seq = capture_sequence(15)

if seq.empty?
  puts 'No bytes captured. Try again or check your terminal settings.'
else
  puts "\n\n=== CAPTURED ==="
  puts 'Byte array (use this in the code):'
  puts "[#{seq.join(', ')}]"
  puts "\nAs chars / escape view:"
  puts seq.map { |b| b < 32 || b > 126 ? "\\x#{b.to_s(16).rjust(2, '0')}" : b.chr }.join
  puts "\nCommon representation:"
  if seq[0] == 27
    csi = seq[1..].map(&:chr).join
    puts "ESC + #{csi.inspect}   (i.e. \\e#{csi.inspect})"
  end
  puts "\nAdd the array above to shift_enter_seqs in PwnAIInput if it is not already present."
end

puts "\nDone. Paste the [n, n, ...] array back to the AI so the list can be updated."
