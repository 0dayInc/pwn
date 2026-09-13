# frozen_string_literal: true

require 'spec_helper'
require 'pty'
require 'timeout'
require 'tmpdir'
require 'io/console'

# Exercise the actual command with curses/getch, real protobuf decoding and a
# real temporary vault. Only broker connection/IO is replaced; no radios open.
describe PWN::Plugins::REPL, 'mesh terminal integration' do
  it 'receives, shows status, switches and persists channels, and leaves menus through real terminal input' do
    Dir.mktmpdir('pwn-mesh-console') do |dir|
      script = File.join(dir, 'console.rb')
      File.write(script, <<~'RUBY')
        require 'pwn'
        require 'meshtastic'
        require 'pwn/plugins/repl'
        require 'ostruct'
        require 'json'
        root = ARGV.fetch(0)
        class FixtureBroker
          attr_reader :client_id
          def initialize(root)
            @root = root
            @client_id = 'aabbccdd'
            @queue = Queue.new
          end
          def subscribe(topic, _qos)
            File.write(File.join(@root, 'topic'), topic)
            # An independent publisher uses the full regional path.
            channel = 'LongFast'
            published = "msh/US/UT/2/e/#{channel}/!11223344"
            return unless published.start_with?(topic.delete_suffix('#'))
            packet = Meshtastic::MeshPacket.new(
              from: 0x11223344, to: 0xffffffff, channel: 8, id: 17,
              decoded: Meshtastic::Data.new(portnum: :TEXT_MESSAGE_APP, payload: "RECEIVED fixture #{channel}")
            )
            @queue << OpenStruct.new(topic: published, payload: Meshtastic::ServiceEnvelope.new(packet: packet).to_proto)
          end
          def get_packet
            loop do
              packet = @queue.pop
              break unless packet
              yield packet
            end
          end
          def disconnect
            @queue.close
          end
        end
        PWN.const_set(:Env, {}) unless PWN.const_defined?(:Env)
        path = File.join(root, 'pwn.yaml')
        dec = "#{path}.decryptor"
        PWN::Env.replace(
          driver_opts: { pwn_env_path: path, pwn_dec_path: dec },
          ai: { active: 'untouched-fixture' },
          plugins: { meshtastic: {
            transport: 'mqtt', mqtt: { host: 'fixture-broker', port: 1883 },
            channel: {
              active: 'LongFast',
              LongFast: { region: 'US/UT', topic: '2/e/#', psk: 'AQ==', channel_num: 8 }
            }
          } }
        )
        File.write(path, YAML.dump(PWN::Env))
        PWN::Plugins::Vault.create(file: path, decryptor_file: dec)
        repl = PWN::Plugins::REPL
        repl.singleton_class.send(:define_method, :mesh_connect) do |opts|
          PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
          PWN.const_set(:MeshTransport, :mqtt)
          FixtureBroker.new(root)
        end
        repl.singleton_class.send(:define_method, :mesh_disconnect) { |opts| opts[:obj].disconnect }
        repl.add_hooks
        repl.add_commands
        pi = Pry.new(quiet: true)
        begin
          pi.run_command('pwn-mesh')
          puts 'RETURNED_TO_PRY'
        rescue Exception => e
          Curses.close_screen
          warn "#{e.class}: #{e.message}"
          exit 1
        end
      RUBY
      transcript = +''
      status = nil
      PTY.spawn({ 'TERM' => 'xterm-256color', 'LANG' => 'C.UTF-8' },
                RbConfig.ruby, '-Ilib', script, dir) do |reader, writer, pid|
        writer.winsize = [32, 110]
        await_text = lambda do |text|
          Timeout.timeout(15) do
            transcript << reader.readpartial(16_384) until transcript.include?(text)
          end
        end
        begin
          await_text.call('RECEIVED fixture LongFast')
          writer.write("/status\r")
          await_text.call('active channel=LongFast')
          writer.write("/menu\r")
          await_text.call('toggle-dispatch-to-pwn-ai')
          # Escape closes the picker; the next command must not be swallowed.
          writer.write("\e")
          writer.write("/back\r")
          await_text.call('RETURNED_TO_PRY')
          _, status = Process.wait2(pid)
        ensure
          begin
            Process.kill('TERM', pid) unless status
            Process.wait(pid) unless status
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          end
        end
      end
      expect(status.exitstatus).to eq(0), transcript
      transcript.force_encoding(Encoding::UTF_8)
      expect(transcript).to include('╭', '─', 'COMPOSE', 'CONVERSATION')
      expect(File.read(File.join(dir, 'topic'))).to eq('msh/US/UT/2/e/LongFast/#')
      path = File.join(dir, 'pwn.yaml')
      expect(PWN::Plugins::Vault.file_encrypted?(file: path)).to be(true)
      decryptor = YAML.load_file("#{path}.decryptor", symbolize_names: true)
      PWN::Plugins::Vault.decrypt(file: path, **decryptor)
      cfg = YAML.load_file(path, symbolize_names: true)
      expect(cfg.dig(:plugins, :meshtastic, :channel, :active)).to eq('LongFast')
      expect(cfg.dig(:ai, :active)).to eq('untouched-fixture')
    end
  end
end
