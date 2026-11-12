# frozen_string_literal: true

require 'spec_helper'

describe 'domain analysis error propagation' do
  {
    PWN::AI::Agent::Assembly => { type: :asm_to_opcodes, arch: :x64, endian: :little },
    PWN::AI::Agent::BTC => {},
    PWN::AI::Agent::BurpSuite => {},
    PWN::AI::Agent::GQRX => { location: 'offline fixture' },
    PWN::AI::Agent::HackerOne => { type: :scope_details },
    PWN::AI::Agent::SAST => {},
    PWN::AI::Agent::TransparentBrowser => { source_to_review: 'const value = 1;' }
  }.each do |agent, options|
    context agent.to_s do
      it 'preserves validation errors before reflection' do
        expect(PWN::AI::Agent::Reflect).not_to receive(:on)
        expect { agent.analyze(options) }.to raise_error(RuntimeError, 'ERROR: request parameter is required')
      end

      it 'preserves the provider exception and its original backtrace' do
        failure = IOError.new('offline provider failure')
        failure.set_backtrace(['fixture_provider.rb:12:in `chat`'])
        allow(PWN::AI::Agent::Reflect).to receive(:on).and_raise(failure)

        expect { agent.analyze(options.merge(request: 'fixture input')) }.to raise_error do |error|
          expect(error).to equal(failure)
          expect(error.backtrace).to eq(['fixture_provider.rb:12:in `chat`'])
        end
      end
    end
  end
end
