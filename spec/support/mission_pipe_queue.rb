# frozen_string_literal: true

require 'json'

# Real IPC barriers for examples whose producer lives in a mission child.
class PWNTestPipeQueue
  # Process-local, not thread-local: a worker can construct a queue too.
  CREATED = Queue.new
  private_constant :CREATED

  def self.close_created
    while (queue = CREATED.pop(timeout: 0))
      queue.close
    end
  end

  def initialize
    @reader, @writer = IO.pipe
    @mutex = Mutex.new
    CREATED << self
  end

  def <<(value)
    @mutex.synchronize { @writer.write("#{JSON.generate(value)}\n") }
    self
  end

  def pop
    JSON.parse(@reader.gets, symbolize_names: true)
  end

  def empty?
    @reader.wait_readable(0).nil?
  end

  def close
    @reader.close unless @reader.closed?
    @writer.close unless @writer.closed?
  end
end

RSpec.configure do |config|
  config.after { PWNTestPipeQueue.close_created }
end
