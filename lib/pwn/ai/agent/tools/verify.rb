# frozen_string_literal: true

require 'digest'
require 'json'
require 'socket'
require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'verify',
  toolset: 'sessions',
  schema: {
    name: 'verify',
    description: 'Run machine-checkable acceptance checks (file_exists, file_sha256, file_grep, port_open, http_status, cmd_exit0).',
    parameters: {
      type: 'object',
      properties: {
        checks: { type: 'array' }
      },
      required: %w[checks]
    }
  },
  handler: lambda { |args|
    checks = Array(args[:checks] || args['checks'])
    results = checks.map do |row|
      row = {} unless row.is_a?(Hash)
      type = (row[:type] || row['type']).to_s
      a = row[:args] || row['args'] || row
      case type
      when 'file_exists'
        path = (a[:path] || a['path']).to_s
        { type: type, passed: File.file?(path), path: path }
      when 'file_sha256'
        path = (a[:path] || a['path']).to_s
        want = (a[:sha256] || a['sha256']).to_s
        have = File.file?(path) ? Digest::SHA256.file(path).hexdigest : ''
        { type: type, passed: !want.empty? && have == want, path: path }
      when 'file_grep'
        path = (a[:path] || a['path']).to_s
        rx = (a[:pattern] || a['pattern']).to_s
        body = File.file?(path) ? File.read(path) : ''
        { type: type, passed: !rx.empty? && body.match?(Regexp.new(rx)), path: path }
      when 'port_open'
        host = (a[:host] || a['host'] || '127.0.0.1').to_s
        port = (a[:port] || a['port']).to_i
        ok = begin
          TCPSocket.new(host, port).close
          true
        rescue StandardError
          false
        end
        { type: type, passed: ok, host: host, port: port }
      when 'http_status'
        { type: type, passed: false, error: 'use TransparentBrowser for HTTP checks' }
      when 'cmd_exit0'
        cmd = (a[:command] || a['command']).to_s
        { type: type, passed: system(cmd) == true }
      else
        { type: type, passed: false, error: 'unknown check type' }
      end
    end
    { passed: results.all? { |r| r[:passed] }, results: results }
  }
)
