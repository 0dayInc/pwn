# frozen_string_literal: true

require 'json'

# Real IPC barriers for examples whose producer lives in a mission child.
class PWNTestPipeQueue
  def initialize
    @reader, @writer = IO.pipe
    @mutex = Mutex.new
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
  config.after { ObjectSpace.each_object(PWNTestPipeQueue, &:close) }
end
