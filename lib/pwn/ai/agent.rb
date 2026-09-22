# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SAST modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    # Collection of Agentic AI Modules. These modules are designed to perform specific tasks autonomously, such as interacting with APIs, performing reconnaissance, or automating exploitation steps. Each module is designed to be used within an agentic AI framework, allowing for the creation of intelligent agents that can perform complex tasks without human intervention. The Agent module serves as a namespace for all agentic AI modules, providing a structured way to organize and access these functionalities. By using autoload, we ensure that each module is only loaded into memory when it's actually needed, optimizing resource usage and improving performance.
    module Agent
      # Agentic AI Modules
      autoload :Assembly, 'pwn/ai/agent/assembly'
      autoload :BTC, 'pwn/ai/agent/btc'
      autoload :BurpSuite, 'pwn/ai/agent/burp_suite'
      autoload :HackerOne, 'pwn/ai/agent/hacker_one'
      autoload :GQRX, 'pwn/ai/agent/gqrx'
      autoload :SAST, 'pwn/ai/agent/sast'
      autoload :SkillConsolidation, 'pwn/ai/agent/skill_consolidation'
      autoload :SkillReview, 'pwn/ai/agent/skill_review'
      autoload :TransparentBrowser, 'pwn/ai/agent/transparent_browser'
      autoload :VulnGen, 'pwn/ai/agent/vuln_gen'

      # ---- pwn-ai native tool-calling harness ----
      autoload :Registry, 'pwn/ai/agent/registry'
      autoload :RequestRuntime, 'pwn/ai/agent/request_runtime'
      autoload :Profiles, 'pwn/ai/agent/profiles'
      autoload :EngagementMemory, 'pwn/ai/agent/engagement_memory'
      autoload :Dispatch, 'pwn/ai/agent/dispatch'
      autoload :Confirmation, 'pwn/ai/agent/confirmation'
      autoload :Result,        'pwn/ai/agent/result'
      autoload :PromptBuilder, 'pwn/ai/agent/prompt_builder'
      autoload :Loop, 'pwn/ai/agent/loop'
      autoload :Manifest, 'pwn/ai/agent/manifest'
      autoload :Metrics, 'pwn/ai/agent/metrics'
      autoload :Learning,      'pwn/ai/agent/learning'
      autoload :Mistakes,      'pwn/ai/agent/mistakes'
      autoload :Extrospection, 'pwn/ai/agent/extrospection'
      autoload :Reflect,       'pwn/ai/agent/reflect'
      autoload :Swarm,         'pwn/ai/agent/swarm'
      autoload :Reward,        'pwn/ai/agent/reward'
      autoload :Verification,  'pwn/ai/agent/verification'
      autoload :Curriculum,    'pwn/ai/agent/curriculum'
      autoload :TaskSummarizer, 'pwn/ai/agent/task_summarizer'
      autoload :TaskDAG, 'pwn/ai/agent/task_dag'
      autoload :Policy, 'pwn/ai/agent/policy'
      autoload :PolicyEvaluation, 'pwn/ai/agent/policy_evaluation'
      autoload :ToolGuard, 'pwn/ai/agent/tool_guard'
      autoload :TurnFinalizer, 'pwn/ai/agent/turn_finalizer'
      autoload :Engagement, 'pwn/ai/agent/engagement'
      autoload :Mission, 'pwn/ai/agent/mission'
      autoload :OpenGoal, 'pwn/ai/agent/open_goal'
      autoload :PromptCache, 'pwn/ai/agent/prompt_cache'

      # Display a List of Every PWN::AI Module

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Display a List of Every PWN::AI Module
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
