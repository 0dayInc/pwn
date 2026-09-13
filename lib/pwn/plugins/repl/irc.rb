# frozen_string_literal: true

require 'json'
require 'pry'

module PWN
  module Plugins
    module REPL
      # pwn-irc REPL mode.
      module IRC
        # Register Pry commands for this REPL mode.
        public_class_method def self.add_commands
          Pry::Commands.create_command 'pwn-irc' do
            description 'IRC viewport onto a PWN::AI::Agent::Swarm (deprecated as multi-agent transport).'

            # pwn-irc is now a THIN OBSERVER over PWN::AI::Agent::Swarm.
            # The old inspircd/weechat block spun up N text-only .chat bots
            # per nick — that bypassed tools, Memory, Skills, Learning,
            # Metrics and Extrospection. Multi-agent now lives in
            # PWN::AI::Agent::Swarm (agent_ask / agent_debate / agent_broadcast
            # from inside pwn-ai). This command just bridges a swarm's
            # bus.jsonl into an IRC channel so you can watch in weechat and
            # type `@red enumerate ports on 10.0.0.5` to route into Swarm.ask.
            def process
              host = '127.0.0.1'
              port = 6667
              chan = '#pwn'

              unless PWN::Plugins::Sock.check_port_in_use(server_ip: host, port: port)
                puts <<~MIGRATE
                  pwn-irc is now an optional viewport onto PWN::AI::Agent::Swarm.
                  Multi-agent no longer requires IRC:

                    pwn-ai
                    » agent_list
                    » agent_debate(names: %w[red blue], topic: '...', rounds: 3)

                  or from Ruby:
                    PWN::AI::Agent::Swarm.debate(names: %w[red blue], topic: '...')

                  Personas: #{PWN::AI::Agent::Swarm::AGENTS_FILE}
                  Bus     : ~/.pwn/swarm/<swarm_id>/bus.jsonl

                  (Start inspircd on #{host}:#{port} if you still want the weechat view.)
                MIGRATE
                return
              end

              personas = PWN::AI::Agent::Swarm.personas
              if personas.empty?
                puts "No personas defined in #{PWN::AI::Agent::Swarm::AGENTS_FILE} — " \
                     'use PWN::AI::Agent::Swarm.spawn or agent_spawn from pwn-ai.'
                return
              end

              swarm  = PWN::AI::Agent::Swarm.create(topic: 'pwn-irc bridge')
              sid    = swarm[:swarm_id]
              bus    = swarm[:bus]
              ui     = ENV.fetch('USER', 'human')
              bridge = 'swarmbot'

              irc = PWN::Plugins::IRC.connect(host: host.to_s, port: port.to_s, nick: bridge)
              PWN::Plugins::IRC.join(irc_obj: irc, nick: bridge, chan: chan)
              PWN::Plugins::IRC.privmsg(
                irc_obj: irc, nick: bridge, chan: chan,
                message: "*** swarm #{sid} bridged | personas: #{personas.keys.join(', ')} " \
                         "| say '@<persona> <request>' | tailing #{bus}"
              )

              # bus.jsonl → #pwn
              tailer = Thread.new do
                seen = File.exist?(bus) ? File.foreach(bus).count : 0
                loop do
                  lines = File.exist?(bus) ? File.readlines(bus) : []
                  lines[seen..].to_a.each do |l|
                    m = JSON.parse(l, symbolize_names: true)
                    PWN::Plugins::IRC.privmsg(
                      irc_obj: irc, nick: bridge, chan: chan,
                      message: "[#{m[:from]}→#{m[:to]}] #{m[:content].to_s.tr("\n", ' ')[0, 400]}"
                    )
                  rescue StandardError
                    next
                  end
                  seen = lines.length
                  sleep 1
                end
              end

              # #pwn '@persona ...' → Swarm.ask
              listener = Thread.new do
                PWN::Plugins::IRC.listen(irc_obj: irc) do |raw|
                  next unless raw.to_s.split[1] == 'PRIVMSG'

                  body = raw.to_s.split(' :', 2).last.to_s
                  from = raw.to_s.split('!').first.to_s.delete_prefix(':')
                  m    = body.match(/@(\w+)\s+(.+)/)
                  next unless m && personas.key?(m[1].to_sym)

                  begin
                    PWN::AI::Agent::Swarm.ask(
                      name: m[1], request: m[2], swarm_id: sid, from: from
                    )
                  rescue StandardError => e
                    PWN::Plugins::IRC.privmsg(
                      irc_obj: irc, nick: bridge, chan: chan,
                      message: "[error] #{m[1]}: #{e.class}: #{e.message[0, 200]}"
                    )
                  end
                end
              end

              if File.exist?('/usr/bin/weechat')
                cmds = [
                  "/server add pwn #{host}/#{port} -notls", '/connect pwn',
                  "/wait 3 /allserv /nick #{ui}", "/wait 4 /join -server pwn #{chan}"
                ].join(';')
                system('/usr/bin/weechat', '--run-command', "'#{cmds}'")
              else
                puts "Bridging swarm #{sid} on ##{chan} (weechat not found — use any IRC client). Ctrl-C to stop."
                listener.join
              end
            ensure
              tailer&.kill
              listener&.kill
              PWN::Plugins::IRC.quit(irc_obj: irc) if defined?(irc) && irc
            end
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display usage for this module.

        public_class_method def self.help
          puts "USAGE:
            # Register the pwn-irc Pry command.
            #{self}.add_commands

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
