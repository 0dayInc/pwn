#!/usr/bin/env ruby
# frozen_string_literal: true

alias_file = '/etc/profile.d/aliases.sh'
system("sudo touch #{alias_file}")
system("sudo chmod 777 #{alias_file}")
File.open(alias_file, 'w') do |f|
  f.puts '#!/bin/bash'
  f.puts "alias grep='grep --color=auto'"
  f.puts "alias kpid='kill -15'"
  f.puts "alias ls='ls --color=auto'"
  f.puts "alias phantomjs='export QT_QPA_PLATFORM=offscreen; phantomjs'"
  f.puts "alias prep='ps -ef | grep'"
  f.puts "alias sup='sudo -i'"
  f.puts "alias vi='vim -i NONE -b'"
  f.puts "alias vim='vim -i NONE -b'"
  f.puts "alias tmux='TERM=screen-256color tmux'"
end
system("sudo chmod 755 #{alias_file}")
