# frozen_string_literal: true

# require 'concurrent-ruby'

module PWN
  module Plugins
    # This plugin makes the creation of a thread pool much simpler.
    module ThreadPool
      # Supported Method Parameters::
      # PWN::Plugins::ThreadPool.fill(
      #   enumerable_array: 'required array for proper thread pool assignment',
      #   max_threads: 'optional number of threads in the thread pool (defaults to 9)',
      #   detach: 'optional boolean to detach threads (defaults to false)'
      # )
      #
      # Example:
      # arr = [1, 2, 3, 4, 5, 6, 7, 8, 9]
      # mutex = Mutex.new
      # PWN::Plugins::ThreadPool.fill(enumerable_array: arr, max_threads: 9) do |integer|
      #   mutex.synchronize do
      #     puts integer
      #   end
      # end

      # public_class_method def self.fill(opts = {})
      #   enumerable_array = opts[:enumerable_array]
      #   max_threads = opts[:max_threads].to_i
      #   max_threads = 9 if max_threads.zero?
      #   detach = opts[:detach] ||= false

      #   puts "Initiating Thread Pool of #{max_threads} Worker Threads...."
      #   pool = Concurrent::FixedThreadPool.new(max_threads)

      #   enumerable_array.each do |this_thread|
      #     pool.post do
      #       yield this_thread
      #     end
      #   end

      #   pool.shutdown
      #   pool.wait_for_termination unless detach
      # rescue Interrupt
      #   puts "\nGoodbye."
      # rescue StandardError => e
      #   puts e.backtrace
      #   raise e
      # end
      # METHOD ABOVE IS SLOWER THAN THE ONE BELOW

      public_class_method def self.fill(opts = {})
        enumerable_array = opts[:enumerable_array]
        max_threads = opts[:max_threads].to_i
        max_threads = 9 if max_threads.zero?
        detach = opts[:detach] ||= false

        puts "Initiating Thread Pool of #{max_threads} Worker Threads...."
        queue = SizedQueue.new(max_threads)
        threads = Array.new(max_threads) do
          Thread.new do
            until (this_thread = queue.pop) == :POOL_EXHAUSTED
              yield this_thread
            end
          end
        end

        enumerable_array.uniq.each do |this_thread|
          queue << this_thread
        end

        max_threads.times do
          queue << :POOL_EXHAUSTED
        end

        threads.each(&:join) unless detach
      rescue Interrupt
        puts "\nGoodbye."
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.fill(
            enumerable_array. => 'required array for proper thread pool assignment',
            max_threads: 'optional number of threads in the thread pool (defaults to 9)',
            detach: 'optional boolean to detach threads (defaults to false)'
          )

          Example:
          arr = [1, 2, 3, 4, 5, 6, 7, 8, 9]
          #{self}.fill(enumerable_array: arr, max_threads: 9) do |integer|
            puts integer
          end

          #{self}.authors
        "
      end
    end
  end
end
