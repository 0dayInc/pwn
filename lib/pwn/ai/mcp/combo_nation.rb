# frozen_string_literal: true

require 'json'
require 'open3'
require 'timeout'

module PWN
  module AI
    module MCP
      # JSON-RPC 2.0 / MCP 2024-11-05 stdio client for combo.nation.
      # Speaks the native menu-oriented tools over newline-delimited JSON;
      # it does not scrape a terminal or enable hardware unless requested.
      module ComboNation
        PROTOCOL_VERSION = '2024-11-05'
        DEFAULT_COMMAND = '/opt/combo.nation/combo.nation'
        TOOLS = %w[
          menu_catalog menu_main menu_dial_calibration menu_guess
          hardware_connect operation_status operation_answer operation_cancel servo_pause
        ].freeze

        public_class_method def self.required_bins
          %w[combo.nation]
        end

        # Build the combo.nation MCP argv. Hardware remains off unless requested.

        public_class_method def self.argv(opts = {})
          command = (opts[:command] || DEFAULT_COMMAND).to_s
          raise ArgumentError, 'command is required' if command.empty?

          argv = [command, '--mcp']
          Array(opts[:args]).each { |arg| argv << arg.to_s }
          argv << '--mcp-allow-hardware' if opts[:allow_hardware]
          argv
        end

        # Spawn or attach to combo.nation --mcp and complete initialize.

        public_class_method def self.connect(opts = {})
          timeout = (opts[:timeout] || 5).to_f
          allow_hardware = opts[:allow_hardware] ? true : false
          reader = opts[:reader]
          writer = opts[:writer]
          stdin = stdout = stderr = wait_thr = nil
          unless reader && writer
            command = argv(opts)
            begin
              stdin, stdout, stderr, wait_thr = Open3.popen3(*command)
            rescue Errno::ENOENT
              raise IOError, "combo.nation MCP executable not found: #{command.first}. Build combo.nation or pass command: to #{self}.connect."
            end
            reader = stdout
            writer = stdin
          end
          session = {
            reader: reader,
            writer: writer,
            stdin: stdin,
            stdout: stdout,
            stderr: stderr,
            wait_thr: wait_thr,
            mutex: Mutex.new,
            next_id: 1,
            timeout: timeout,
            allow_hardware: allow_hardware,
            stderr_buf: +''
          }
          drain_stderr(session: session)
          begin
            result = request(
              session: session,
              method: 'initialize',
              params: {
                'protocolVersion' => PROTOCOL_VERSION,
                'capabilities' => {},
                'clientInfo' => { 'name' => 'pwn', 'version' => PWN::VERSION.to_s }
              }
            )
            notify(session: session, method: 'notifications/initialized')
            session[:protocol_version] = result['protocolVersion']
            session[:server_info] = result['serverInfo']
            session
          rescue StandardError
            disconnect(session: session)
            raise
          end
        end

        # Close the MCP stdio session and reap a spawned combo.nation process.

        public_class_method def self.disconnect(opts = {})
          session = opts[:session]
          return unless session.is_a?(Hash)

          close_io(io: session[:writer])
          if session[:wait_thr]
            begin
              Timeout.timeout(session[:timeout] || 5) { session[:wait_thr].value }
            rescue Timeout::Error
              begin
                Process.kill('TERM', session[:wait_thr].pid)
              rescue StandardError
                nil
              end
              begin
                session[:wait_thr].value
              rescue StandardError
                nil
              end
            end
          end
          close_io(io: session[:reader])
          close_io(io: session[:stderr])
          session[:stderr_thread]&.join(1)
          session
        end

        # Send a JSON-RPC request and return its result object.

        public_class_method def self.request(opts = {})
          session = session!(opts)
          method = opts[:method].to_s
          raise ArgumentError, 'method is required' if method.empty?

          params = opts[:params]
          timeout = (opts[:timeout] || session[:timeout] || 5).to_f
          session[:mutex].synchronize do
            ident = session[:next_id]
            session[:next_id] += 1
            message = { 'jsonrpc' => '2.0', 'id' => ident, 'method' => method }
            message['params'] = params unless params.nil?
            write_line(session: session, message: message)
            response = read_json(session: session, timeout: timeout)
            raise IOError, 'combo.nation MCP closed stdout' if response.nil?
            raise IOError, 'combo.nation MCP response id mismatch' unless response['id'] == ident

            if response['error']
              error = response['error']
              raise IOError, "combo.nation MCP error #{error['code']}: #{error['message']}"
            end
            response['result']
          end
        end

        # Send a JSON-RPC notification with no response.

        public_class_method def self.notify(opts = {})
          session = session!(opts)
          method = opts[:method].to_s
          raise ArgumentError, 'method is required' if method.empty?

          message = { 'jsonrpc' => '2.0', 'method' => method }
          message['params'] = opts[:params] unless opts[:params].nil?
          session[:mutex].synchronize { write_line(session: session, message: message) }
          method
        end

        # MCP ping.

        public_class_method def self.ping(opts = {})
          request(session: opts[:session], method: 'ping')
        end

        # MCP tools/list.

        public_class_method def self.list_tools(opts = {})
          result = request(session: opts[:session], method: 'tools/list')
          Array(result && result['tools'])
        end

        # MCP tools/call with JSON text payloads parsed when possible.

        public_class_method def self.call_tool(opts = {})
          name = opts[:name].to_s
          raise ArgumentError, 'name is required' if name.empty?

          arguments = opts[:arguments]
          arguments = {} if arguments.nil?
          raise ArgumentError, 'arguments must be a Hash' unless arguments.is_a?(Hash)

          result = request(
            session: opts[:session],
            method: 'tools/call',
            params: { 'name' => name, 'arguments' => stringify(value: arguments) }
          )
          parse_tool_result(result: result)
        end

        # List actual main, dial calibration, and guess menus with string IDs.

        public_class_method def self.menu_catalog(opts = {})
          call_tool(session: opts[:session], name: 'menu_catalog')
        end

        # Select a main-menu option by exact string ID.

        public_class_method def self.menu_main(opts = {})
          menu_call(session: opts[:session], name: 'menu_main', option: opts[:option])
        end

        # Select a dial-calibration option by exact string ID.

        public_class_method def self.menu_dial_calibration(opts = {})
          menu_call(session: opts[:session], name: 'menu_dial_calibration', option: opts[:option])
        end

        # Select a guess-menu option by exact string ID such as 5.10.

        public_class_method def self.menu_guess(opts = {})
          menu_call(session: opts[:session], name: 'menu_guess', option: opts[:option])
        end

        # Start hardware initialization; requires --mcp-allow-hardware on the server.

        public_class_method def self.hardware_connect(opts = {})
          call_tool(session: opts[:session], name: 'hardware_connect')
        end

        # Read the current operation, pending prompt, and hardware flags.

        public_class_method def self.operation_status(opts = {})
          call_tool(session: opts[:session], name: 'operation_status')
        end

        # Answer the pending prompt by id.

        public_class_method def self.operation_answer(opts = {})
          prompt_id = opts[:prompt_id]
          raise ArgumentError, 'prompt_id is required' if prompt_id.nil?
          raise ArgumentError, 'value is required' unless opts.key?(:value)

          call_tool(
            session: opts[:session],
            name: 'operation_answer',
            arguments: { 'prompt_id' => prompt_id, 'value' => opts[:value] }
          )
        end

        # Request cooperative cancellation of the active operation.

        public_class_method def self.operation_cancel(opts = {})
          call_tool(session: opts[:session], name: 'operation_cancel')
        end

        # Pause or resume the current servo move.

        public_class_method def self.servo_pause(opts = {})
          action = opts[:action].to_s
          raise ArgumentError, 'action is required' unless %w[pause resume].include?(action)

          call_tool(session: opts[:session], name: 'servo_pause', arguments: { 'action' => action })
        end

        # Poll operation_status until a terminal or requested state.

        public_class_method def self.poll_until(opts = {})
          session = opts[:session]
          wanted = Array(opts[:states] || %w[completed failed cancelled]).map(&:to_s)
          interval = (opts[:interval] || 1).to_f
          timeout = (opts[:timeout] || 30).to_f
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          loop do
            status = operation_status(session: session)
            state = status.dig(:parsed, 'state').to_s
            return status if wanted.include?(state)

            raise Timeout::Error, "combo.nation operation still #{state.inspect}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

            sleep interval if interval.positive?
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # List host binaries this module expects to be installed.
            #{self}.required_bins

            # Build combo.nation MCP argv without launching a process.
            #{self}.argv(
              command: 'optional - combo.nation executable path (default #{DEFAULT_COMMAND})',
              args: 'optional - extra argv after --mcp',
              allow_hardware: 'optional - append --mcp-allow-hardware (default false)'
            )

            # Spawn or attach to combo.nation --mcp and complete MCP initialize.
            #{self}.connect(
              command: 'optional - combo.nation executable path (default #{DEFAULT_COMMAND})',
              args: 'optional - extra argv after --mcp',
              allow_hardware: 'optional - pass --mcp-allow-hardware (default false; never implied)',
              timeout: 'optional - seconds for handshake and subsequent reads (default 5)',
              reader: 'optional - IO providing server stdout for tests',
              writer: 'optional - IO consuming server stdin for tests'
            )

            # Close pipes and reap a spawned combo.nation process.
            #{self}.disconnect(
              session: 'required - Hash returned by connect'
            )

            # Send a JSON-RPC 2.0 request and return its result object.
            #{self}.request(
              session: 'required - Hash returned by connect',
              method: 'required - JSON-RPC method name such as ping or tools/list',
              params: 'optional - Hash or Array params object',
              timeout: 'optional - seconds to wait for this response'
            )

            # Send a JSON-RPC notification that expects no response.
            #{self}.notify(
              session: 'required - Hash returned by connect',
              method: 'required - notification method such as notifications/initialized',
              params: 'optional - Hash params object'
            )

            # Send an MCP ping request.
            #{self}.ping(
              session: 'required - Hash returned by connect'
            )

            # List tools advertised by the combo.nation MCP server.
            #{self}.list_tools(
              session: 'required - Hash returned by connect'
            )

            # MCP tools/call; JSON text content is parsed when valid.
            #{self}.call_tool(
              session: 'required - Hash returned by connect',
              name: 'required - tool name advertised by tools/list',
              arguments: 'optional - Hash of tool arguments (string menu IDs stay strings)'
            )

            # List actual application menus and exact string option IDs.
            #{self}.menu_catalog(
              session: 'required - Hash returned by connect'
            )

            # Select a main-menu option by exact string ID.
            #{self}.menu_main(
              session: 'required - Hash returned by connect',
              option: 'required - exact menu ID string such as 0.3'
            )

            # Select a dial-calibration option by exact string ID.
            #{self}.menu_dial_calibration(
              session: 'required - Hash returned by connect',
              option: 'required - exact menu ID string such as 3.99'
            )

            # Select a guess-menu option by exact string ID.
            #{self}.menu_guess(
              session: 'required - Hash returned by connect',
              option: 'required - exact menu ID string such as 5.10'
            )

            # Start hardware initialization; the server still requires --mcp-allow-hardware.
            #{self}.hardware_connect(
              session: 'required - Hash returned by connect'
            )

            # Read the current operation, pending prompt, updates, and hardware flags.
            #{self}.operation_status(
              session: 'required - Hash returned by connect'
            )

            # Answer the pending prompt by id.
            #{self}.operation_answer(
              session: 'required - Hash returned by connect',
              prompt_id: 'required - integer prompt id from operation_status',
              value: 'required - number, exact option string, rotation plan, or true for ack'
            )

            # Request cooperative cancellation of the active operation.
            #{self}.operation_cancel(
              session: 'required - Hash returned by connect'
            )

            # Pause or resume the current servo move.
            #{self}.servo_pause(
              session: 'required - Hash returned by connect',
              action: 'required - pause or resume'
            )

            # Poll operation_status until a requested state; the first reply is not completion.
            #{self}.poll_until(
              session: 'required - Hash returned by connect',
              states: 'optional - Array of state strings (default completed failed cancelled)',
              interval: 'optional - seconds between polls (default 1)',
              timeout: 'optional - seconds before Timeout::Error (default 30)'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
        end

        private_class_method def self.session!(opts = {})
          session = opts[:session]
          raise ArgumentError, 'session is required' unless session.is_a?(Hash) && session[:reader] && session[:writer]

          session
        end

        private_class_method def self.menu_call(opts = {})
          option = opts[:option].to_s
          raise ArgumentError, 'option is required' if option.empty?

          call_tool(session: opts[:session], name: opts[:name], arguments: { 'option' => option })
        end

        private_class_method def self.write_line(opts = {})
          session = opts[:session]
          session[:writer].write("#{JSON.generate(opts[:message])}\n")
          session[:writer].flush
        end

        private_class_method def self.read_json(opts = {})
          session = opts[:session]
          line = Timeout.timeout(opts[:timeout]) { session[:reader].gets }
          return if line.nil?

          JSON.parse(line)
        end

        private_class_method def self.parse_tool_result(opts = {})
          result = opts[:result] || {}
          text = result.dig('content', 0, 'text')
          parsed = begin
            JSON.parse(text)
          rescue JSON::ParserError, TypeError
            text
          end
          {
            content: result['content'],
            is_error: result['isError'] == true,
            text: text,
            parsed: parsed
          }
        end

        private_class_method def self.stringify(opts = {})
          value = opts[:value]
          depth = opts.fetch(:depth, 0)
          raise JSON::NestingError, 'MCP arguments exceed JSON nesting limit (100)' if depth >= 100 && (value.is_a?(Hash) || value.is_a?(Array))

          case value
          when Hash
            value.to_h { |key, child| [key.to_s, stringify(value: child, depth: depth + 1)] }
          when Array
            value.map { |child| stringify(value: child, depth: depth + 1) }
          else
            value
          end
        end

        private_class_method def self.drain_stderr(opts = {})
          session = opts[:session]
          stderr = session[:stderr]
          return unless stderr

          session[:stderr_thread] = Thread.new do
            Thread.current.report_on_exception = false
            stderr.each { |chunk| session[:stderr_buf] << chunk }
          rescue IOError, Errno::EPIPE
            nil
          end
        end

        private_class_method def self.close_io(opts = {})
          io = opts[:io]
          io.close unless io.nil? || io.closed?
        rescue IOError
          nil
        end
      end
    end
  end
end
