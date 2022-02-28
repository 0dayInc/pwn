# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin makes the creation of a thread pool much simpler.
    module ThreadPool
      # Supported Method Parameters::
      # PWN::Plugins::ThreadPool.fill(
      #   enumerable_array: 'required array for proper thread pool assignment',
      #   :max_threads: 'optional number of threads in the thread pool (defaults to 9)',
      #   &block
      # )
      #
      # Example:
      # arr = [1, 2, 3, 4, 5, 6, 7, 8, 9]
      # PWN::Plugins::ThreadPool.fill(enumerable_array: arr, max_threads: 9) do |integer|
      #   puts integer
      # end

      public_class_method def self.fill(opts = {})
        enumerable_array = opts[:enumerable_array]
        opts[:max_threads].nil? ? max_threads = 9 : max_threads = opts[:max_threads].to_i

        puts "Initiating Thread Pool of #{max_threads} Worker Threads...."
        queue = SizedQueue.new(max_threads)
        threads = Array.new(max_threads) do
          Thread.new do
            until (this_thread = queue.pop) == :END
              yield this_thread
            end
          end
        end
        enumerable_array.uniq.sort.each { |this_thread| queue << this_thread }
        max_threads.times { queue << :END }
        threads.each(&:join)
      rescue Interrupt
        puts "\nGoodbye."
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
          #{self}.fill(
            enumerable_array. => 'required array for proper thread pool assignment',
            max_threads: 'optional number of threads in the thread pool (defaults to 9)',
            &block
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
