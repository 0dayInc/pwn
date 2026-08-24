# frozen_string_literal: true

module PWN
  module AI
    # This file, using the autoload directive loads AI RedTeam modules
    # into memory only when they're needed. For more information, see:
    # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
    #
    # PWN::AI::RedTeam is the AI/LLM analogue of PWN::SAST - a collection of
    # adversarial test-case modules that exhaustively analyze / fuzz Large
    # Language Models for AI-specific vulnerabilities (prompt injection,
    # jailbreaks, system-prompt extraction, sensitive-data disclosure,
    # excessive agency, insecure output handling, supply chain, poisoning,
    # unbounded consumption, hidden context, vector stores, RAG, MCP/A2A,
    # and memory persistence). Each module maps to an OWASP LLM Top-10
    # category and a MITRE ATLAS technique so findings roll straight into
    # PWN::Reports::AIRedTeam.
    module RedTeam
      # OWASP LLM Top-10 / MITRE ATLAS aligned AI RedTeam modules
      autoload :AgentProtocolAbuse, 'pwn/ai/red_team/agent_protocol_abuse'
      autoload :DataAndModelPoisoning, 'pwn/ai/red_team/data_and_model_poisoning'
      autoload :ExcessiveAgency, 'pwn/ai/red_team/excessive_agency'
      autoload :HiddenContextExposure, 'pwn/ai/red_team/hidden_context_exposure'
      autoload :InsecureOutputHandling, 'pwn/ai/red_team/insecure_output_handling'
      autoload :Jailbreak, 'pwn/ai/red_team/jailbreak'
      autoload :MemoryPoisoning, 'pwn/ai/red_team/memory_poisoning'
      autoload :MultimodalInjection, 'pwn/ai/red_team/multimodal_injection'
      autoload :Overreliance, 'pwn/ai/red_team/overreliance'
      autoload :PayloadSplitting, 'pwn/ai/red_team/payload_splitting'
      autoload :PromptInjection, 'pwn/ai/red_team/prompt_injection'
      autoload :RagPoisoning, 'pwn/ai/red_team/rag_poisoning'
      autoload :SensitiveInformationDisclosure, 'pwn/ai/red_team/sensitive_information_disclosure'
      autoload :SupplyChain, 'pwn/ai/red_team/supply_chain'
      autoload :SystemPromptExtraction, 'pwn/ai/red_team/system_prompt_extraction'
      autoload :TokenSmuggling, 'pwn/ai/red_team/token_smuggling'
      autoload :UnboundedConsumption, 'pwn/ai/red_team/unbounded_consumption'
      autoload :VectorAndEmbeddingWeaknesses, 'pwn/ai/red_team/vector_and_embedding_weaknesses'

      # This module executes all the other AI RedTeam modules
      autoload :TestCaseEngine, 'pwn/ai/red_team/test_case_engine'

      # Display a List of Every PWN::AI::RedTeam Module

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
