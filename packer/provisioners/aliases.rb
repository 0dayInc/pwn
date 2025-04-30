#!/usr/bin/env ruby
# frozen_string_literal: true

alias_file = '/etc/profile.d/aliases.sh'
system("sudo touch #{alias_file}")
system("sudo chmod 777 #{alias_file}")
File.open(alias_file, 'w') do |f|
  f.puts '#!/bin/bash'
  f.puts "alias file='file --keep-going --raw'"
  f.puts "alias grep='grep --color=auto'"
  f.puts "alias kpid='kill -15'"
  f.puts "alias ls='ls --color=auto'"
  f.puts "alias phantomjs='export QT_QPA_PLATFORM=offscreen; phantomjs'"
  f.puts "alias prep='ps -ef | grep'"
  f.puts "alias r2='setarch $(uname -m) -R /usr/local/bin/r2 -c \"v r2-pwn-layout\" -c \"decai -e model=0dayInc:latest\" -c \"decai -e cmds=pdc\" -c \"decai -e prompt=Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change \"goto\" into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like \"string:\", Reduce lines of code and fit everything in a single function, removing all dead code.  Most importantly, determine if this code is exploitable.\"'"
  f.puts "alias sup='sudo -i'"
  f.puts "alias vi='vim -i NONE -b'"
  f.puts "alias vim='vim -i NONE -b'"
  f.puts "alias tmux='TERM=screen-256color tmux'"
end
system("sudo chmod 755 #{alias_file}")
