# frozen_string_literal: true

require 'spec_helper'

# ─────────────────────────────────────────────────────────────────────────────
#  #4 — Result.condition is the ONLY thing standing between PWN::Env
#  secrets and the model. NON-BLOCKING: pure string in / string out.
#
#  Fixture credentials are built by concatenation (exactly as
#  Result::REDACT_PATTERNS builds its regexes) so nothing token-shaped
#  lands in git as a literal.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::AI::Agent::Result.condition — redaction & truncation', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  let(:result)   { PWN::AI::Agent::Result }
  let(:registry) { PWN::AI::Agent::Registry }

  it 'truncates over-cap output and appends a […truncated N chars] marker' do
    entry = registry::Entry.new(name: 't', max_chars: 100)
    big   = 'A' * 5_000
    out   = result.condition(content: big, entry: entry)
    expect(out.length).to be < 200
    expect(out).to match(/truncated 4900 chars/)
    expect(out).to start_with('A' * 100)
  end

  it 'redacts every REDACT_PATTERNS credential shape' do
    fixtures = {
      openai: %w[s k -].join + ('A' * 40),
      slack: %w[x o x b -].join + ('a1b2c3d4e5' * 2),
      github: %w[g h p _].join + ('A' * 36),
      aws: %w[A K I A].join + ('B' * 16),
      google: %w[A I z a].join + ('C' * 35),
      privkey: "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    }
    fixtures.each do |kind, tok|
      out = result.redact(content: "before #{tok} after")
      expect(out).to include('<<<REDACTED>>>'), "#{kind}: not redacted"
      expect(out).not_to include(tok), "#{kind}: token survived"
      expect(out).to include('before ').and include(' after')
    end
  end

  it 'redacts SENSITIVE_KEYS values pulled from PWN::Env at any depth' do
    secret = 'super-secret-value-xyz'
    allow(result).to receive(:env_credential_values).and_call_original
    PWN::Env[:svc] = { api_key: secret, nested: { token: 'anothertoken!' } }
    out = result.redact(content: "leak #{secret} and anothertoken! done")
    expect(out).not_to include(secret)
    expect(out).not_to include('anothertoken!')
    expect(out.scan('<<<REDACTED>>>').length).to be >= 2
  ensure
    PWN::Env.delete(:svc)
  end

  it 'does NOT over-redact benign look-alikes' do
    benign = [
      "text#{%w[A K I A].join}text", # AKIA embedded in a word (regex requires 16 [0-9A-Z] tail)
      "#{%w[s k -].join}short",         # sk- but < 20 chars
      'SGVsbG8gd29ybGQ='                # ordinary short base64
    ]
    benign.each do |b|
      expect(result.redact(content: b)).to eq(b), "over-redacted benign: #{b.inspect}"
    end
  end

  it '.condition composes truncation THEN redaction' do
    tok   = %w[s k -].join + ('Z' * 40)
    entry = registry::Entry.new(name: 't', max_chars: 200)
    out   = result.condition(content: "#{tok} " * 50, entry: entry)
    expect(out).not_to include(tok)
    expect(out).to include('<<<REDACTED>>>')
    expect(out).to match(/truncated \d+ chars/)
  end
end
