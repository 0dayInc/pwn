# frozen_string_literal: true

require 'nokogiri'

module PWN
  module Plugins
    # This plugin is used for interacting w/ baresip over a screen session.
    module BareSIP
      @@logger = PWN::Plugins::PWNLogger.create
      @session_data = []
      # Supported Method Parameters::
      # baresip_http_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   cmd: 'required rest call to make per the schema',
      # )

      private_class_method def self.baresip_http_call(opts = {})
        baresip_obj = opts[:baresip_obj]
        cmd = opts[:cmd]
        http_listen_ip_port = baresip_obj[:http_listen_ip_port]
        baresip_url = "http://#{http_listen_ip_port}"

        max_conn_attempts = 30
        conn_attempt = 0

        begin
          conn_attempt += 1

          rest_client = PWN::Plugins::TransparentBrowser.open(
            browser_type: :rest
          )::Request

          response = rest_client.execute(
            method: :get,
            url: "#{baresip_url}/?#{cmd}",
            verify_ssl: false
          )

          Nokogiri::HTML.parse(response)
        rescue Errno::ECONNREFUSED
          raise e if conn_attempt > max_conn_attempts

          sleep 1
          retry
        end
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      end

      # Supported Method Parameters::
      # baresip_obj = PWN::Plugins::BareSIP.start(
      #   src_num: 'Optional source phone number displayed',
      #   baresip_bin: 'Optional path of baresip binary (Defaults to /usr/bin/baresip)',
      #   config_root: 'Optional dir of baresip config (Defaults to ~/.baresip)',
      #   session_root: 'Optional dir of baresip session (Defaults to Dir.pwd)',
      #   screen_session: 'Optional name of screen session (Defaults baresip)'
      # )

      public_class_method def self.start(opts = {})
        src_num = opts[:src_num]

        baresip_bin = opts[:baresip_bin] if File.exist?(
          opts[:baresip_bin].to_s
        )
        baresip_bin ||= '/usr/bin/baresip'

        baresip_obj = {}

        session_root = opts[:session_root] if Dir.exist?(opts[:session_root].to_s)

        config_root = opts[:config_root] if Dir.exist?(
          opts[:config_root].to_s
        )
        config_root ||= "#{Dir.home}/.baresip"

        config = "#{config_root}/config"
        config_lines = File.readlines(config)
        http_list_entry = config_lines.grep(/^http_listen\s.+$/)

        raise "no http_listen value found in #{config}." if http_list_entry.empty?

        http_listen_ip_port = http_list_entry.last.split.grep(/:/).last

        screen_session = opts[:screen_session]
        screen_session ||= 'baresip'

        baresip_obj[:config_root] = config_root
        baresip_obj[:http_listen_ip_port] = http_listen_ip_port
        baresip_obj[:session_root] = session_root
        baresip_obj[:screen_session] = screen_session

        screenlog_file = 'screenlog.txt'
        baresip_obj[:screenlog_file] = screenlog_file

        # Prefer running baresip in detached screen vs --daemon mode
        # Since sndfile doesn't produce .wav files in --daemon mode
        system(
          'screen',
          '-T',
          'xterm',
          '-L',
          '-Logfile',
          screenlog_file,
          '-S',
          screen_session,
          '-d',
          '-m',
          baresip_bin,
          '-f',
          config_root,
          '-e',
          '/insmod httpd',
          '-e',
          '/insmod sndfile'
        )

        baresip_obj[:session_thread] = init_session_thread(
          baresip_obj: baresip_obj
        )

        ok = 'registered successfully'
        gone = 'account: No SIP accounts found'
        forb = '403 Forbidden'

        # TODO: Make this faster.
        print 'Starting baresip...'
        loop do
          break if @session_data.select { |s| s.include?(ok) }.length.positive?

          next unless dump_session_data.select { |s| s.include?(gone) }.length.positive?
          next unless dump_session_data.select { |s| s.include?(forb) }.length.positive?

          error = gone if dump_session_data.select { |s| s.include?(gone) }.length.positive?
          error = forbid if dump_session_data.select { |s| s.include?(forb) }.length.positive?
          raise "Something happened when attempting to start baresip: #{error}"
        end
        puts 'ready.'

        baresip_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # session_thread = init_session_thread(
      #   serial_conn: 'required - SerialPort.new object'
      # )

      private_class_method def self.init_session_thread(opts = {})
        baresip_obj = opts[:baresip_obj]

        session_root = baresip_obj[:session_root]
        screenlog_file = baresip_obj[:screenlog_file]

        screenlog = "#{session_root}/#{screenlog_file}"

        # Spin up a baresip_obj session_thread
        Thread.new do
          loop do
            next unless File.exist?(screenlog)

            # Continuously consume contents of screenlog.0
            @session_data = File.readlines(screenlog)
            @session_data.delete_if do |line|
              line.include?('ua: using best effort AF: af=AF_INET')
            end
          end
        end
      rescue StandardError => e
        session_thread&.terminate

        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::BareSIP.dump_session_data

      public_class_method def self.dump_session_data
        @session_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::BareSIP.flush_session_data

      public_class_method def self.flush_session_data
        @session_data.clear
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # cmd_resp = PWN::Plugins::BareSIP.baresip_exec(
      #   baresip_obj: 'Required - baresip obj returned from #start method',
      #   cmd: 'Required - command to send to baresip HTTP daemon'
      # )

      public_class_method def self.baresip_exec(opts = {})
        baresip_obj = opts[:baresip_obj]
        cmd = opts[:cmd]

        baresip_http_call(
          baresip_obj: baresip_obj,
          cmd: cmd
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BareSIP.stop(
      #   screen_session: 'Required - screen session to stop'
      # )

      public_class_method def self.stop(opts = {})
        baresip_obj = opts[:baresip_obj]
        session_thread = baresip_obj[:session_thread]
        screen_session = baresip_obj[:screen_session]

        flush_session_data

        session_thread.terminate

        system(
          'screen',
          '-X',
          '-S',
          screen_session,
          'quit'
        )

        baresip_obj = nil
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BareSIP.parse_target_file(
      #   target_file: 'Required - txt file containing phone numbers to dial',
      #   randomize: 'Optional - randomize list of phone numbers to dial (Defaults to false)'
      # )

      public_class_method def self.parse_target_file(opts = {})
        target_file = opts[:target_file]
        randomize = opts[:randomize]

        # Parse entries from target_file and build out our target range
        target_lines = File.readlines(target_file)
        target_range = []
        print 'Initializing targets...'
        target_lines.each do |target_line|
          next if target_line.match?(/^#.*$/)

          target_line.scrub.strip.chomp.delete('(').delete(')').delete('.').delete('+')
          if target_line.include?('-')
            split_range = target_line.split('-')
            if split_range.length == 2
              from_num = split_range.first.to_i
              to_num = split_range.last.to_i

              (from_num..to_num).each do |number_in_range|
                target_range.push(number_in_range)
              end
            else
              target_line.scrub.strip.chomp.delete('-')
            end
          else
            target_range.push(target_line.to_i)
          end
        end
        puts 'complete.'

        # Randomize targets if applicable
        target_range.shuffle! if randomize

        target_range
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BareSIP.apply_src_num_rules(
      #   target_num: 'Required - destination number to derive source number',
      #   src_num_rules: 'Optional - Comma-delimited list of rules for src_num format (i.e. self, same_country, same_area, and/or same_prefix [Defaults to random src_num w/ same length as target_num])'
      # )

      public_class_method def self.apply_src_num_rules(opts = {})
        config_root = opts[:config_root] if Dir.exist?(
          opts[:config_root].to_s
        )
        config_root ||= "#{Dir.home}/.baresip"
        src_num_rules = opts[:src_num_rules]
        target_num = opts[:target_num]

        src_num_rules_arr = []
        if src_num_rules
          src_num_rules_arr = src_num_rules.delete("\s").split(',').map(
            &:to_sym
          )
        end

        case target_num.to_s.length
        when 10
          # area+prefix+suffix
          country = ''
        when 11
          # 1 digit country+area+prefix+suffix
          country = format('%0.1d', Random.rand(1..9))
          country = target_num.to_s.chars.first if src_num_rules_arr.include?(
            :same_country
          )
        when 12
          # 2 digit country+area+prefix+suffix
          country = format('%0.2d', Random.rand(1..99))
          country = target_num.to_s.chars[0..1].join if src_num_rules_arr.include?(
            :same_country
          )
        when 13
          # 3 digit country+area+prefix+suffix
          country = format('%0.3d', Random.rand(1..999))
          country = target_num.to_s.chars[0..2].join if src_num_rules_arr.include?(
            :same_country
          )
        when 14
          # 4 digit country+area+prefix+suffix
          country = format('%0.4d', Random.rand(1..9999))
          country = target_num.to_s.chars[0..3].join if src_num_rules_arr.include?(
            :same_country
          )
        else
          raise "Target # should be 10-14 digits. Length is: #{target_num.to_s.length}"
        end

        # > 799 for prefix leads to call issues when calling 800 numbers.
        # area = format('%0.3s', Random.rand(200..999))
        area = format('%0.3d', Random.rand(200..999))
        area = target_num.to_s.chars[-10..-8].join if src_num_rules_arr.include?(
          :same_area
        )

        prefix = format('%0.3d', Random.rand(200..999))
        prefix = target_num.to_s.chars[-7..-5].join if src_num_rules_arr.include?(
          :same_prefix
        )
        suffix = format('%0.4d', Random.rand(0..9999))
        src_num = "#{country}#{area}#{prefix}#{suffix}"
        src_num = target_num if src_num_rules_arr.include?(:self)

        # TODO: Update ~/.baresip/accounts to apply source number
        sip_accounts_path = "#{config_root}/accounts"
        updated_account_content = ''
        File.read(sip_accounts_path).each_line do |line|
          this_account_line = line
          if line.match?(/^<sip:.+@.+>/)
            sip_account_to_keep = this_account_line.split('@').last
            this_account_line = "<sip:#{src_num}@#{sip_account_to_keep}"
          end
          updated_account_content = "#{updated_account_content}#{this_account_line}"
        end
        File.write(sip_accounts_path, updated_account_content)

        src_num
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BareSIP.recon(
      #   baresip_obj: 'Required - baresip_obj returned from #start method',
      #   target_num: 'Required - target destination to recon (i.e. phone number)',
      #   src_num_rules: 'Optional - Comma-delimited list of rules for src_num format (i.e. self, same_country, same_area, and/or same_prefix [Defaults to random src_num w/ same length as target_num])',
      #   seconds_to_record: 'Optional - Seconds to Record (Defaults to 60)',
      #   sox_bin: 'Optional - Path to SoX Binary, the Swiss Army knife of Audio (Defaults to /usr/bin/sox)'
      # )

      public_class_method def self.recon(opts = {})
        baresip_bin = opts[:baresip_bin]

        config_root = opts[:config_root] if Dir.exist?(
          opts[:config_root].to_s
        )
        config_root ||= "#{Dir.home}/.baresip"

        session_root = opts[:session_root]
        session_root ||= Dir.pwd
        target_file = opts[:target_file]
        randomize = opts[:randomize]
        src_num_rules = opts[:src_num_rules]
        max_threads = opts[:max_threads].to_i
        max_threads = 3 if max_threads.zero?
        seconds_to_record = opts[:seconds_to_record].to_i
        seconds_to_record = 60 if seconds_to_record.zero?
        sox_bin = opts[:sox_bin] if File.exist?(opts[:sox_bin].to_s)
        sox_bin ||= '/usr/bin/sox'
        waveform_bin = 'waveform'

        # Intialize empty baresip obj for ensure block below
        baresip_obj = {}

        # Colors!
        red = "\e[31m"
        green = "\e[32m"
        yellow = "\e[33m"
        cayan = "\e[36m"
        end_of_color = "\e[0m"

        target_range = parse_target_file(
          target_file: target_file,
          randomize: randomize
        )

        results_hash = {
          session_started: Time.now.strftime('%Y-%m-%d_%H.%M.%S'),
          data: []
        }

        # TODO: Multi-thread!
        # mutex = Mutex.new
        # PWN::Plugins::ThreadPool.fill(
        #   enumerable_array: target_range,
        #   max_threads: max_threads
        # ) do |target_num|
        target_range.each_with_index do |target_num, index|
          call_count = index + 1
          puts "Call #{call_count} of #{target_range.length}..."

          # Change to session_root _before_ starting to ensure
          # wav files are stored in the proper location
          Dir.chdir(session_root)

          src_num = apply_src_num_rules(
            config_root: config_root,
            target_num: target_num,
            src_num_rules: src_num_rules
          )

          call_info_hash = {}

          call_started = Time.now.strftime('%Y-%m-%d_%H.%M.%S')

          call_info_hash[:call_started] = call_started
          call_info_hash[:src_num] = src_num
          call_info_hash[:src_num_rules] = src_num_rules
          call_info_hash[:target_num] = target_num

          target_num_root = "#{session_root}/#{target_num}-#{call_started}"

          # TODO: Determine what to do w/ existing Directory
          Dir.mkdir(target_num_root)
          Dir.chdir(target_num_root)

          # Start baresip in detached screen to support commands over HTTP
          # and call recording to wav files
          baresip_obj = start(
            src_num: src_num,
            baresip_bin: baresip_bin,
            session_root: target_num_root,
            screen_session: "#{File.basename($PROGRAM_NAME)}-#{target_num}"
          )

          # session_root = baresip_obj[:session_root]
          config_root = baresip_obj[:config_root]
          config = "#{config_root}/config"

          puts "#{green}#{call_started} >>>#{end_of_color}"
          puts "#{yellow}dialing #{target_num}#{end_of_color}"

          cmd_resp = baresip_exec(
            baresip_obj: baresip_obj,
            cmd: "/dial #{target_num}\r\n"
          )
          puts "/dial #{target_num} RESP:"
          puts cmd_resp.xpath('//pre').text

          cmd_resp = baresip_exec(
            baresip_obj: baresip_obj,
            cmd: "/listcalls\r\n"
          )
          puts '/listcalls RESP:'
          puts cmd_resp.xpath('//pre').text

          puts red
          # Conditions to proceed less than seconds_to_record
          terminated = 'terminated (duration:'
          unavail = '503 Service Unavailable'
          not_found = 'session closed: 404 Not Found'

          reason = 'recording limit reached'
          seconds_recorded = 0
          seconds_to_record.downto(1).each do |countdown|
            seconds_recorded += 1
            print "#{seconds_to_record}s to record - remaining: #{format('%-9.9s', countdown)}"
            print "\r"

            if dump_session_data.select { |s| s.include?(terminated) }.length.positive?
              reason = 'call terminated by other party'
              break
            end

            if dump_session_data.select { |s| s.include?(unavail) }.length.positive?
              reason = 'SIP 503 (service unavailable)'
              break
            end

            if dump_session_data.select { |s| s.include?(not_found) }.length.positive?
              reason = 'SIP 404 (not found)'
              break
            end

            sleep 1
          end
          call_info_hash[:seconds_recorded] = seconds_recorded
          puts end_of_color

          call_stopped = Time.now.strftime('%Y-%m-%d_%H.%M.%S')
          puts "\n#{green}#{call_stopped} >>> #{reason} #{target_num}#{end_of_color}"
          call_info_hash[:call_stopped] = call_stopped
          call_info_hash[:reason] = reason

          recording = ''
          # BUGFIX: Sometimes recordings aren't generated
          # Perhaps because previous session wasn't stopped properly?
          Dir.entries(target_num_root).each do |entry|
            recording = entry if entry.match(/^dump-.+-dec.wav/)
            File.delete(entry) if entry.match(/^dump-.+-enc\.wav$/) && File.exist?(entry)
          end

          call_info_hash[:recording] = '--'
          call_info_hash[:waveform] = '--'
          call_info_hash[:spectrogram] = '--'

          unless recording.empty?
            puts cayan

            call_info_hash[:recording] = "#{target_num}-#{call_started}/#{recording}"

            spectrogram = "#{recording}-spectrogram.png"
            print "Generating Audio Spectrogram for #{recording}..."
            system(
              sox_bin,
              recording,
              '-n',
              'spectrogram',
              '-o',
              spectrogram,
              '-d',
              seconds_to_record.to_s
            )
            puts 'complete.'
            call_info_hash[:spectrogram] = "#{target_num}-#{call_started}/#{spectrogram}"

            waveform = "#{recording}-waveform.png"
            print "Generating Audio Waveform for #{recording}..."
            system(
              waveform_bin,
              '--method',
              'peak',
              '--color',
              '#FF0000',
              '--background',
              '#000000',
              '--force',
              recording,
              waveform
            )
            puts 'complete.'
            call_info_hash[:waveform] = "#{target_num}-#{call_started}/#{waveform}"
            puts end_of_color
          end

          # Push Call Results to results_hash[:data]
          # mutex.synchronize do
          #   results_hash[:data].push(call_info_hash)
          # end
          results_hash[:data].push(call_info_hash)

          puts "call termination reason: #{reason}"
          # Stop call to cd into next session root
          stop(baresip_obj: baresip_obj)

          seconds_to_delay_between_pool_of_calls = Random.rand(1..9)
          seconds_to_delay_between_pool_of_calls.downto(1).each do |countdown|
            print "#{red}ZZZ #{seconds_to_delay_between_pool_of_calls}s until next pool of calls: #{format('%-9.9s', countdown)}#{end_of_color}"
            print "\r"
            sleep 1
          end
          puts "\n#{green}waking up for next call \\o/#{end_of_color}"
          puts "\n\n\n"
        end
        results_hash[:session_ended] = Time.now.strftime('%Y-%m-%d_%H.%M.%S')

        results_hash
      rescue StandardError => e
        raise e
      ensure
        stop(baresip_obj: baresip_obj) unless baresip_obj.empty?
      end

      # Supported Method Parameters::
      # PWN::Plugins::BareSIP.killall

      public_class_method def self.killall
        system(
          'killall',
          '-15',
          'baresip'
        )
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
          baresip_obj = #{self}.start(
            baresip_bin: 'Optional path of baresip binary (Defaults to /usr/bin/baresip)'
            config_root: 'Optional dir of baresip config (Defaults to ~/.baresip)',
            screen_session: 'Optional name of screen session (Defaults baresip)'
          )

          session_data_arr = #{self}.dump_session_data

          cmd_resp = #{self}.baresip_exec(
            baresip_obj: 'Required - baresip obj returned from #start method',
            cmd: 'Required - command to send to baresip HTTP daemon'
          )

          stopped_bool = #{self}.stop(
            screen_session: 'Required - screen session to stop'
          )

          #{self}.killall

          #{self}.authors
        "
      end
    end
  end
end
