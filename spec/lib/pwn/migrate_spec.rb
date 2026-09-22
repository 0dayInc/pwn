# frozen_string_literal: true

require 'spec_helper'

describe PWN::Migrate do
  it 'should display information for authors' do
    authors_response = PWN::Migrate
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Migrate
    expect(help_response).to respond_to :help
  end

  it 'exposes the schema / state-file data tables' do
    expect(PWN::Migrate::SCHEMA_VERSION).to be_a(Integer)
    expect(PWN::Migrate::STATE_FILES).to be_a(Hash)
    expect(PWN::Migrate::STATE_FILES).to have_key('pwn.yaml')
    expect(PWN::Migrate::MIGRATIONS).to be_a(Hash)
    expect(PWN::Migrate::MIGRATIONS.keys.max).to eq(PWN::Migrate::SCHEMA_VERSION)
  end

  it 'env_template is the pure hash used for vault backfill' do
    t = PWN::Config.env_template
    expect(t).to be_a(Hash)
    expect(t).to have_key(:ai)
    expect(t[:ai]).to have_key(:agent)
    expect(PWN::Migrate.env_template).to eq(t)
  end

  # ────────────────────────────────────────────────────────────────────
  #  functional round-trip in a tmp sandbox — never touches real ~/.pwn
  # ────────────────────────────────────────────────────────────────────
  context 'sandboxed ~/.pwn', :aggregate_failures do
    include_context 'pwn tmp sandbox'

    let(:io) { StringIO.new }

    before do
      # Skills verifier globs the REAL PWN::Config.pwn_skills_path unless
      # redirected — keep it inside the sandbox too.
      allow(PWN::Config).to receive(:pwn_skills_path).and_return(File.join(@tmp, 'skills'))
    end

    it '.needed? / .status on a fresh (empty) root' do
      expect(PWN::Migrate.installed_schema).to eq(0)
      expect(PWN::Migrate.needed?).to be true

      st = PWN::Migrate.status
      expect(st[:schema_installed]).to eq(0)
      expect(st[:schema_current]).to eq(PWN::Migrate::SCHEMA_VERSION)
      expect(st[:files]).to be_an(Array)
      # only pwn.yaml is REQUIRED to exist; every other absent file is ok:true
      missing_vault = st[:files].find { |f| f[:rel] == 'pwn.yaml' }
      expect(missing_vault[:ok]).to be false
    end

    it '.run applies migrations, stamps .schema, and clears needed?' do
      r = PWN::Migrate.run(fix: false, backup: false, io: io)
      expect(r[:applied_migrations]).to include(1)
      expect(File).to exist(File.join(@tmp, '.schema'))
      expect(PWN::Migrate.installed_schema).to eq(PWN::Migrate::SCHEMA_VERSION)
      expect(PWN::Migrate.needed?).to be false
      # migration 1 seeds the state subdirs
      %w[skills sessions swarm cron curriculum finetune extrospection].each do |d|
        expect(File).to be_directory(File.join(@tmp, d))
      end
    end

    it 'upgrades schema 2 personas with an unset model without changing explicit selections' do
      path = File.join(@tmp, 'agents.yml')
      original = {
        'custom' => { 'role' => 'keep', 'engine' => 'grok', 'extra' => { 'untouched' => true } },
        'pinned' => { 'role' => 'review', 'engine' => 'openai', 'model' => 'Exact/Model:Tag' },
        'default' => { 'role' => 'default', 'model' => nil },
        'blank' => { 'role' => 'blank', 'model' => '' }
      }
      File.write(path, YAML.dump(original))
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 2))
      expect(described_class.needed?).to be(true)
      result = described_class.run(fix: false, backup: false, io: io)
      expect(result[:applied_migrations]).to eq([3, 4, 5])
      expected = Marshal.load(Marshal.dump(original))
      expected['custom']['model'] = nil
      expect(YAML.safe_load_file(path)).to eq(expected)
      expect(described_class.installed_schema).to eq(described_class::SCHEMA_VERSION)
      bytes = File.binread(path)
      described_class::MIGRATIONS.fetch(3).call(@tmp, io)
      expect(File.binread(path)).to eq(bytes)
      expect(described_class.run(fix: false, backup: false, io: io)[:applied_migrations]).to eq([])
    end

    it 'does not create a persona file when applying the model migration without one' do
      described_class::MIGRATIONS.fetch(3).call(@tmp, io)
      expect(File).not_to exist(File.join(@tmp, 'agents.yml'))
    end

    it 'schema 2 patches stock escalator/scribe toolsets and leaves engines alone' do
      File.write(File.join(@tmp, 'agents.yml'), <<~YML)
        ---
        scribe:
          role: report
          engine: grok
          toolsets: [memory, skills, learning, sessions]
        escalator:
          role: hint
          engine: grok
          toolsets: [terminal, pwn, memory]
        custom_coach:
          role: keep my tools
          engine: grok
          toolsets: [terminal, pwn, memory]
      YML
      PWN::Migrate.run(fix: false, backup: false, io: io)
      raw = YAML.safe_load_file(File.join(@tmp, 'agents.yml'), permitted_classes: [Symbol], symbolize_names: true)
      expect(Array(raw[:escalator][:toolsets] || raw[:escalator]['toolsets'])).to eq([])
      expect(Array(raw[:scribe][:toolsets] || raw[:scribe]['toolsets'])).to include('pwn')
      expect(raw[:escalator][:engine] || raw[:escalator]['engine']).to eq('grok')
      expect(Array(raw[:custom_coach][:toolsets] || raw[:custom_coach]['toolsets'])).to include('terminal')
    end

    it 'detects & autofixes a corrupt JSON store (quarantine)' do
      File.write(File.join(@tmp, 'metrics.json'), '{{{ not json')
      st = PWN::Migrate.status
      row = st[:files].find { |f| f[:rel] == 'metrics.json' }
      expect(row[:ok]).to be false
      expect(row[:why]).to match(/unparsable/)

      PWN::Migrate.run(fix: true, backup: false, io: io)
      expect(File).not_to exist(File.join(@tmp, 'metrics.json'))
      expect(Dir.glob(File.join(@tmp, 'quarantine', '*', 'metrics.json'))).not_to be_empty
      # owner falls back cleanly after quarantine
      expect(PWN::AI::Agent::Metrics.load).to eq(tools: {}, updated_at: nil)
    end

    it 'detects & autofixes bad JSONL lines without losing good history' do
      path = File.join(@tmp, 'learning.jsonl')
      File.write(path, %({"task":"a","success":true}\nNOT JSON\n{"task":"b","success":false}\n))
      row = PWN::Migrate.status[:files].find { |f| f[:rel] == 'learning.jsonl' }
      expect(row[:ok]).to be false
      expect(row[:why]).to match(%r{1/3})

      PWN::Migrate.run(fix: true, backup: false, io: io)
      kept = File.readlines(path)
      expect(kept.length).to eq(2)
      kept.each { |l| expect { JSON.parse(l) }.not_to raise_error }
    end

    it 'detects legacy flat skills and converts them (fix: :skills)' do
      sroot = File.join(@tmp, 'skills')
      FileUtils.mkdir_p(sroot)
      File.write(File.join(sroot, 'legacy_probe.md'), "# legacy\n\nBody line.\n")
      row = PWN::Migrate.status[:files].find { |f| f[:rel] == 'skills/' }
      expect(row[:ok]).to be false

      PWN::Migrate.run(fix: true, backup: false, io: io)
      expect(File).to exist(File.join(sroot, 'legacy-probe', 'SKILL.md'))
      expect(Dir.glob(File.join(sroot, '*.md'))).to be_empty
    end

    it 'deep_defaults never overwrites a user value' do
      user = { ai: { active: 'anthropic', anthropic: { key: 'sk-LIVE' } } }
      tmpl = PWN::Config.env_template
      merged = PWN::Migrate.send(:deep_defaults, user: user, tmpl: tmpl)
      expect(merged[:ai][:active]).to eq('anthropic')            # user wins
      expect(merged[:ai][:anthropic][:key]).to eq('sk-LIVE')     # user wins
      expect(merged[:ai][:anthropic]).to have_key(:model)        # backfilled
      expect(merged[:ai]).to have_key(:agent)                    # whole subtree backfilled
      expect(merged).to have_key(:cron)                          # top-level backfilled
    end

    it 'missing_paths reports dotted keys absent from a stale user vault' do
      stale = { ai: { active: 'grok', grok: { key: 'x' } } }
      miss  = PWN::Migrate.send(:missing_paths, tmpl: PWN::Config.env_template, user: stale)
      expect(miss).to include('ai.agent')
      expect(miss).to include('ai_sandbox')
      expect(miss).to include('ai_router')
      expect(miss).to include('memory')
      expect(miss).not_to include('ai.active')
    end

    it 'upgrades a schema-3 vault with new pwn.yaml keys without changing user values' do
      yaml = File.join(@tmp, 'pwn.yaml')
      dec = File.join(@tmp, 'pwn.yaml.decryptor')
      stale = { ai: { active: 'grok', grok: { key: 'sk-KEEP' } } }
      File.write(yaml, YAML.dump(stale).gsub(/^(\s*):/, '\1'))
      PWN::Plugins::Vault.create(file: yaml, decryptor_file: dec)
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 3))
      expect(described_class.needed?).to be(true)
      result = described_class.run(fix: true, backup: false, io: io)
      expect(result[:applied_migrations]).to eq([4, 5])
      creds = YAML.safe_load_file(dec, symbolize_names: true)
      user = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      expect(user[:ai][:active]).to eq('grok')
      expect(user[:ai][:grok][:key]).to eq('sk-KEEP')
      expect(user[:ai_sandbox]).to eq('off')
      expect(user[:ai_router]).to be_a(Hash)
      expect(user[:ai_router][:summarize] || user[:ai_router]['summarize']).to be_a(Hash)
      routes = user.dig(:ai, :agent, :model_routes) || user.dig('ai', 'agent', 'model_routes')
      expect(routes).to include(:exploit_dev).or include('exploit_dev')
      second = described_class.run(fix: true, backup: false, io: io)
      expect(second[:applied_migrations]).to eq([])
      again = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      expect(again[:ai][:grok][:key]).to eq('sk-KEEP')
      expect(described_class.needed?).to be(false)
    end

    it 'upgrades a schema-4 vault with skill_review without changing a user setting' do
      yaml = File.join(@tmp, 'pwn.yaml')
      dec = File.join(@tmp, 'pwn.yaml.decryptor')
      stale = { ai: { active: 'grok', grok: { key: 'sk-KEEP' }, agent: { skill_review: 'off', max_iters: 3 } } }
      missing = { ai: { active: 'openai', openai: { key: 'sk-OTHER' }, agent: { max_iters: 9 } } }
      File.write(yaml, YAML.dump(stale).gsub(/^(\s*):/, '\1'))
      PWN::Plugins::Vault.create(file: yaml, decryptor_file: dec)
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 4))
      result = described_class.run(fix: true, backup: false, io: io)
      expect(result[:applied_migrations]).to eq([5])
      creds = YAML.safe_load_file(dec, symbolize_names: true)
      user = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      expect(user.dig(:ai, :agent, :skill_review)).to eq('off')
      expect(user.dig(:ai, :agent, :max_iters)).to eq(3)
      expect(user.dig(:ai, :grok, :key)).to eq('sk-KEEP')

      File.write(yaml, YAML.dump(missing).gsub(/^(\s*):/, '\1'))
      PWN::Plugins::Vault.encrypt(file: yaml, key: creds[:key], iv: creds[:iv])
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 4))
      described_class.run(fix: true, backup: false, io: io)
      filled = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      expect(filled.dig(:ai, :agent, :skill_review)).to eq('recommend')
      expect(filled.dig(:ai, :agent, :max_iters)).to eq(9)
      expect(filled.dig(:ai, :openai, :key)).to eq('sk-OTHER')
      expect(described_class.run(fix: true, backup: false, io: io)[:applied_migrations]).to eq([])
    end

    it 'dry_run writes nothing' do
      r = PWN::Migrate.run(fix: true, backup: true, dry_run: true, io: io)
      expect(r[:dry_run]).to be true
      expect(File).not_to exist(File.join(@tmp, '.schema'))
      expect(Dir.glob(File.join(@tmp, 'backup', '*'))).to be_empty
    end
  end
end
