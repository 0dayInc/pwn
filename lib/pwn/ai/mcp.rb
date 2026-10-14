# frozen_string_literal: true

require 'json'

module PWN
  module AI
    # Autoload MCP client modules that speak JSON-RPC 2.0 to local MCP servers.
    # Session state lives here so pwn-ai Registry tools persist across turns.
    module MCP
      autoload :ComboNation, 'pwn/ai/mcp/combo_nation'

      @mutex = Mutex.new
      @sessions = {}
      @current = nil

      # List PWN::AI::MCP::* clients that implement the stdio MCP surface.

      public_class_method def self.backends(opts = {})
        opts[:refresh]
        constants.sort.filter_map do |name|
          const = const_get(name)
          next unless const.is_a?(Module)
          next unless %i[connect disconnect list_tools call_tool].all? { |meth| const.respond_to?(meth) }

          {
            name: snake(name: name),
            constant: const.name,
            tools: const.const_defined?(:TOOLS) ? Array(const::TOOLS) : []
          }
        end
      end

      # Resolve a backend name to its client module.

      public_class_method def self.resolve(opts = {})
        key = opts[:backend].to_s
        key = current if key.empty?
        names = backends
        key = names.first[:name] if key.to_s.empty? && names.length == 1
        raise ArgumentError, "backend is required (#{names.map { |row| row[:name] }.join(', ')})" if key.to_s.empty?

        row = names.find { |backend| backend[:name] == key }
        raise ArgumentError, "Unknown MCP backend #{key.inspect}. Known: #{names.map { |backend| backend[:name] }.join(', ')}" unless row

        row.merge(module: const_get(row[:constant].split('::').last))
      end

      # Select the default backend for later /mcp and invoke calls.

      public_class_method def self.use(opts = {})
        key = (opts[:backend] || opts[:name]).to_s
        raise ArgumentError, 'backend is required' if key.empty?

        row = resolve(backend: key)
        @mutex.synchronize { @current = row[:name] }
        { backend: row[:name], constant: row[:constant] }
      end

      # Return the selected default backend name, if any.

      public_class_method def self.current(opts = {})
        opts[:refresh]
        @mutex.synchronize { @current }
      end

      # Connect a backend and remember the session for later mcp tool calls.

      public_class_method def self.connect(opts = {})
        backend = resolve(opts)
        ident = (opts[:session_id] || backend[:name]).to_s
        existing = @mutex.synchronize { @sessions[ident] }
        return summarize(row: existing) if existing && !opts[:force]

        connect_opts = {
          allow_hardware: opts[:allow_hardware],
          timeout: opts[:timeout],
          reader: opts[:reader],
          writer: opts[:writer]
        }
        connect_opts[:command] = opts[:command] if opts[:command]
        connect_opts[:args] = opts[:args] if opts[:args]
        session = backend[:module].connect(connect_opts)
        row = {
          backend: backend[:name],
          session_id: ident,
          constant: backend[:constant],
          module: backend[:module],
          session: session,
          allow_hardware: opts[:allow_hardware] ? true : false
        }
        extra = nil
        @mutex.synchronize do
          if @sessions[ident] && !opts[:force]
            extra = session
            row = @sessions[ident]
          else
            stale = @sessions[ident]
            stale[:module].disconnect(session: stale[:session]) if stale
            @sessions[ident] = row
          end
        end
        backend[:module].disconnect(session: extra) if extra
        @mutex.synchronize { @current = row[:backend] }
        summarize(row: row)
      end

      # Close a remembered MCP session and reap its process.

      public_class_method def self.disconnect(opts = {})
        ident = session_id(opts)
        row = @mutex.synchronize { @sessions.delete(ident) }
        return { disconnected: false, session_id: ident } unless row

        row[:module].disconnect(session: row[:session])
        summarize(row: row).merge(disconnected: true, session_id: ident)
      end

      # MCP ping on a remembered or auto-connected session.

      public_class_method def self.ping(opts = {})
        row = ensure_session(opts)
        { result: row[:module].ping(session: row[:session]) }.merge(summarize(row: row))
      end

      # MCP tools/list on a remembered or auto-connected session.

      public_class_method def self.list_tools(opts = {})
        row = ensure_session(opts)
        { tools: row[:module].list_tools(session: row[:session]) }.merge(summarize(row: row))
      end

      # MCP tools/call on a remembered or auto-connected session.

      public_class_method def self.call_tool(opts = {})
        row = ensure_session(opts)
        name = (opts[:name] || opts[:tool]).to_s
        raise ArgumentError, 'name is required' if name.empty?

        arguments = opts[:arguments] || opts[:params] || {}
        arguments = JSON.parse(arguments) if arguments.is_a?(String) && arguments.strip.start_with?('{')
        raise ArgumentError, 'arguments must be a Hash' unless arguments.is_a?(Hash)

        arguments = stringify(value: arguments)
        reserved = %i[session session_id backend action op name tool arguments params reader writer timeout command allow_hardware force args states interval]
        opts.each do |key, val|
          next if reserved.include?(key.to_sym)
          next if val.nil?

          arguments[key.to_s] = val unless arguments.key?(key.to_s)
        end
        result = row[:module].call_tool(session: row[:session], name: name, arguments: arguments)
        result.merge(summarize(row: row), name: name)
      end

      # Poll operation_status until a requested state.

      public_class_method def self.poll_until(opts = {})
        row = ensure_session(opts)
        raise ArgumentError, "#{row[:constant]} does not implement poll_until" unless row[:module].respond_to?(:poll_until)

        result = row[:module].poll_until(
          session: row[:session],
          states: opts[:states],
          interval: opts[:interval],
          timeout: opts[:timeout]
        )
        result.merge(summarize(row: row))
      end

      # Single Registry entry point for pwn-ai mcp tool calls.

      public_class_method def self.invoke(opts = {})
        args = opts[:args] if opts.key?(:args)
        args = opts unless opts.key?(:args)
        args = {} if args.nil?
        args = args.transform_keys(&:to_sym) if args.respond_to?(:transform_keys)
        action = (args[:action] || args[:op]).to_s
        raise ArgumentError, 'action is required' if action.empty?

        case action
        when 'backends' then { backends: backends }
        when 'use' then use(args)
        when 'current' then { backend: current }
        when 'connect' then connect(args)
        when 'disconnect', 'close' then disconnect(args)
        when 'ping' then ping(args)
        when 'list_tools', 'list' then list_tools(args)
        when 'call_tool', 'call' then call_tool(args)
        when 'poll_until', 'poll' then poll_until(args)
        when 'status'
          ident = session_id(args)
          row = @mutex.synchronize { @sessions[ident] }
          return { connected: false, session_id: ident } unless row

          summarize(row: row).merge(connected: true)
        else
          raise ArgumentError, "Unknown MCP action #{action.inspect}"
        end
      rescue ArgumentError, IOError, Timeout::Error => e
        { error: e.message, action: action }
      end

      # Drop all remembered sessions. Used by tests and shutdown.

      public_class_method def self.reset!(opts = {})
        opts[:force]
        rows = @mutex.synchronize do
          @current = nil
          @sessions.values.tap { @sessions.clear }
        end
        rows.each do |row|
          row[:module].disconnect(session: row[:session])
        rescue StandardError
          nil
        end
        { cleared: rows.length }
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display MCP backends and the pwn-ai session broker.

      public_class_method def self.help
        puts "USAGE:
          # Display a List of Every PWN::AI::MCP Module
          #{self}.authors

          # List MCP client modules under PWN::AI::MCP.
          #{self}.backends(
            refresh: 'optional - ignored placeholder so opts is read'
          )

          # Resolve a backend name to its client module.
          #{self}.resolve(
            backend: 'optional - snake_case PWN::AI::MCP client name; uses current or the only client'
          )

          # Select the default backend for later invoke and /mcp calls.
          #{self}.use(
            backend: 'required - snake_case PWN::AI::MCP client name to select',
            name: 'optional - alias for backend'
          )

          # Return the selected default backend name.
          #{self}.current(
            refresh: 'optional - ignored placeholder so opts is read'
          )

          # Connect a backend and remember the session for later tool calls.
          #{self}.connect(
            backend: 'optional - selected client, or the only PWN::AI::MCP client when just one exists',
            session_id: 'optional - session key (default backend name)',
            allow_hardware: 'optional - pass --mcp-allow-hardware (default false)',
            command: 'optional - executable path forwarded to the backend',
            args: 'optional - extra argv forwarded to the backend',
            timeout: 'optional - handshake timeout seconds',
            reader: 'optional - test IO replacing process stdout',
            writer: 'optional - test IO replacing process stdin',
            force: 'optional - replace an existing remembered session'
          )

          # Close a remembered MCP session.
          #{self}.disconnect(
            backend: 'optional - backend name used as the default session id',
            session_id: 'optional - session key to close'
          )

          # Send an MCP ping on a remembered or auto-connected session.
          #{self}.ping(
            backend: 'optional - backend to auto-connect when no session exists',
            session_id: 'optional - session key',
            reader: 'optional - test IO used only when auto-connecting',
            writer: 'optional - test IO used only when auto-connecting',
            timeout: 'optional - seconds forwarded on auto-connect'
          )

          # List tools advertised by a remembered or auto-connected session.
          #{self}.list_tools(
            backend: 'optional - backend to auto-connect when no session exists',
            session_id: 'optional - session key',
            reader: 'optional - test IO used only when auto-connecting',
            writer: 'optional - test IO used only when auto-connecting',
            timeout: 'optional - seconds forwarded on auto-connect'
          )

          # Call an MCP tool on a remembered or auto-connected session.
          #{self}.call_tool(
            backend: 'optional - backend to auto-connect when no session exists',
            session_id: 'optional - session key',
            name: 'required - MCP tool name advertised by the selected backend',
            tool: 'optional - alias for name',
            arguments: 'optional - Hash of MCP tool arguments (string IDs stay strings)',
            params: 'optional - alias for arguments',
            reader: 'optional - test IO used only when auto-connecting',
            writer: 'optional - test IO used only when auto-connecting',
            timeout: 'optional - seconds forwarded on auto-connect',
            command: 'optional - executable path forwarded on auto-connect',
            allow_hardware: 'optional - hardware flag used only when auto-connecting'
          )

          # Poll until an MCP operation reaches a requested state.
          #{self}.poll_until(
            backend: 'optional - backend to auto-connect when no session exists',
            session_id: 'optional - session key',
            states: 'optional - Array of state strings',
            interval: 'optional - seconds between polls',
            timeout: 'optional - seconds before Timeout::Error'
          )

          # Single pwn-ai Registry entry point.
          #{self}.invoke(
            action: 'required - backends, use, current, connect, disconnect, ping, list_tools, call_tool, poll_until, or status',
            op: 'optional - alias for action',
            args: 'optional - Hash of the same keys when wrapping Dispatch args',
            backend: 'optional - snake_case PWN::AI::MCP client name',
            session_id: 'optional - session key',
            name: 'optional - MCP tool name for call_tool',
            arguments: 'optional - Hash of MCP tool arguments',
            allow_hardware: 'optional - hardware flag for connect only'
          )

          # Drop all remembered sessions.
          #{self}.reset!(
            force: 'optional - ignored placeholder so opts is read'
          )
        "
        constants.sort
      end

      private_class_method def self.snake(opts = {})
        opts[:name].to_s.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
      end

      private_class_method def self.session_id(opts = {})
        return opts[:session_id].to_s unless opts[:session_id].to_s.empty?
        return opts[:backend].to_s unless opts[:backend].to_s.empty?

        resolve(opts)[:name]
      end

      private_class_method def self.ensure_session(opts = {})
        ident = session_id(opts)
        row = @mutex.synchronize { @sessions[ident] }
        return row if row

        connect(opts)
        @mutex.synchronize { @sessions[ident] }
      end

      private_class_method def self.summarize(opts = {})
        row = opts[:row]
        {
          backend: row[:backend],
          session_id: row[:session_id] || row[:backend],
          constant: row[:constant],
          allow_hardware: row[:allow_hardware]
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
    end
  end
end
