# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'logger'

# ─────────────────────────────────────────────────────────────────────────────
#  #9 — 48 SAST modules, all currently only respond_to-tested. This is
#  the biggest USER-FACING correctness gap: SAST is what most `pwn_sast`
#  consumers actually run.
#
#  Table-driven: one {hit:, miss:} fixture pair per module → write to a
#  tmpdir → mod.scan(dir_path:) → assert ≥1 / 0 findings AND that every
#  finding hash carries the report contract keys.
#
#  NON-BLOCKING: pure grep + file I/O in tmpdir; PWN::AI::Agent::SAST
#  (LLM analysis) and the class-var Logger are stubbed. Fixtures avoid
#  the .js-beautify path in TestCaseEngine so no external bin is needed.
#
#  Add fixtures incrementally — a module absent from FIXTURES is simply
#  not exercised (the 348 stub specs still assert its shape).
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::SAST — functional hit/miss', :aggregate_failures do
  fixtures = {
    'PWN::SAST::Eval' => { ext: '.rb', hit: 'eval(params[:x])', miss: 'evaluate(x)' },
    'PWN::SAST::CmdExecutionRuby' => { ext: '.rb', hit: 'system("ls")', miss: 'user = 1' },
    'PWN::SAST::MD5' => { ext: '.rb', hit: 'Digest::MD5.hexdigest(x)', miss: 'Digest::SHA256.hexdigest(x)' },
    'PWN::SAST::Base64' => { ext: '.rb', hit: 'Base64.decode64(secret)', miss: 'x = 64' },
    'PWN::SAST::InnerHTML' => { ext: '.html', hit: 'el.innerHTML = user;', miss: 'el.textContent = user;' },
    'PWN::SAST::AWS' => { ext: '.rb', hit: 'aws_access_key_id = "x"', miss: 'region = "us-east-1"' },
    'PWN::SAST::PrivateKey' => { ext: '.pem', hit: '-----BEGIN RSA PRIVATE KEY-----', miss: '-----BEGIN PUBLIC KEY-----' },
    'PWN::SAST::BeefHook' => { ext: '.html', hit: '<script src="http://x/hook.js">', miss: '<script src="app.js">' }
  }

  before do
    allow(PWN::AI::Agent::SAST).to receive(:analyze).and_return('N/A') if defined?(PWN::AI::Agent::SAST)
    PWN::SAST::TestCaseEngine.class_variable_set(:@@logger, Logger.new(File::NULL))
    @prev_ai = PWN::Env[:ai]
    PWN::Env[:ai] = { active: :ollama, module_reflection: false, agent: {} }
  end

  after { PWN::Env[:ai] = @prev_ai }

  fixtures.each do |const, fx|
    describe const do
      let(:mod) do
        Object.const_get(const)
      rescue LoadError, NameError => e
        skip "#{const}: unavailable (#{e.class})"
      end

      it 'security_references carries the report contract keys' do
        refs = mod.security_references
        expect(refs).to include(:sast_module, :section, :nist_800_53_uri, :cwe_id, :cwe_uri)
        expect(refs[:sast_module]).to eq(mod)
      end

      it 'detects the anti-pattern in :hit and stays silent on :miss' do
        Dir.mktmpdir('pwn_sast_hit') do |d|
          # NOTE: filenames must NOT match /test/i (TestCaseEngine skips them)
          File.write(File.join(d, "sample_hit#{fx[:ext]}"), "#{fx[:hit]}\n")
          findings = mod.scan(dir_path: d)
          expect(findings).to be_an(Array)
          expect(findings.length).to be >= 1, 'expected ≥1 finding for :hit fixture'
          h = findings.first
          expect(h).to include(:timestamp, :security_references, :filename, :line_no_and_contents,
                               :raw_content, :test_case_filter)
          expect(Array(h[:line_no_and_contents]).first).to include(:line_no, :contents)
        end

        Dir.mktmpdir('pwn_sast_miss') do |d|
          File.write(File.join(d, "sample_miss#{fx[:ext]}"), "#{fx[:miss]}\n")
          findings = mod.scan(dir_path: d)
          expect(findings).to eq([]), "expected 0 findings for :miss fixture, got #{findings.length}"
        end
      end
    end
  end
end
