# frozen_string_literal: true

require 'spec_helper'

describe PWN::Migrate, 'exact migration snapshot scope' do
  include_context 'pwn tmp sandbox'

  it 'backs up nested registry paths and directory trees without cron runtime copies' do
    FileUtils.mkdir_p(File.join(@tmp, 'cron', 'schedule-backups'))
    FileUtils.mkdir_p(File.join(@tmp, 'skills', 'custom'))
    File.write(File.join(@tmp, 'cron', 'jobs.yml'), "--- []\n")
    File.write(File.join(@tmp, 'cron', 'worker.log'), 'diagnostic')
    File.write(File.join(@tmp, 'cron', 'schedule-backups', 'receipt.json'), '{}')
    File.write(File.join(@tmp, 'skills', 'custom', 'SKILL.md'), 'custom recovery')
    snapshot = described_class.send(:backup!)
    expect(File.read(File.join(snapshot, 'cron', 'jobs.yml'))).to eq("--- []\n")
    expect(File.read(File.join(snapshot, 'skills', 'custom', 'SKILL.md'))).to eq('custom recovery')
    expect(File).not_to exist(File.join(snapshot, 'cron', 'worker.log'))
    expect(File).not_to exist(File.join(snapshot, 'cron', 'schedule-backups'))
  end

  it 'does not require new cron logs and maintenance copies in recovery coverage' do
    File.write(File.join(@tmp, 'memory.json'), '{}')
    5.times do |i|
      path = File.join(described_class::BACKUP_ROOT, "2026010#{i + 1}_000000")
      FileUtils.mkdir_p(path)
      File.write(File.join(path, 'memory.json'), '{}')
    end
    FileUtils.mkdir_p(File.join(@tmp, 'cron', 'schedule-backups'))
    File.write(File.join(@tmp, 'cron', 'worker.log'), 'new diagnostic')
    File.write(File.join(@tmp, 'cron', 'schedule-backups', 'receipt.json'), '{}')
    result = described_class.prune_backups(dry_run: false, expire_history: true)
    expect(result[:deleted]).to eq(%w[20260101_000000 20260102_000000])
    expect(File.read(File.join(@tmp, 'cron', 'worker.log'))).to eq('new diagnostic')
  end
end

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

    it 'expires unique old history only after current recovery coverage is established' do
      File.write(File.join(@tmp, 'memory.json'), '{"current":true}')
      4.times do |i|
        path = File.join(PWN::Migrate::BACKUP_ROOT, "2026010#{i + 1}_000000")
        FileUtils.mkdir_p(path)
        File.write(File.join(path, 'memory.json'), i == 3 ? '{"current":true}' : "{\"old\":#{i}}")
      end
      result = PWN::Migrate.prune_backups(dry_run: false, expire_history: true)
      expect(result[:deleted]).to eq(['20260101_000000'])
      expect(result[:retained].length).to eq(3)
      expect(File).to exist(File.join(PWN::Migrate::BACKUP_ROOT, '.retention-manifest.json.gz'))
      expect(File.read(File.join(@tmp, 'memory.json'))).to eq('{"current":true}')
    end

    context 'bounded historical expiry safeguards' do
      before do
        File.write(File.join(@tmp, 'memory.json'), '{}')
        5.times do |i|
          path = File.join(PWN::Migrate::BACKUP_ROOT, "2026010#{i + 1}_000000")
          FileUtils.mkdir_p(path)
          File.write(File.join(path, 'memory.json'), '{}')
        end
      end

      it 'pins actual referenced evidence, not quoted inventory prose' do
        File.write(File.join(@tmp, 'learning.jsonl'), "#{JSON.generate(evidence_path: "#{PWN::Migrate::BACKUP_ROOT}/20260101_000000/memory.json", prose: "old path #{PWN::Migrate::BACKUP_ROOT}/20260102_000000/memory.json")}\n")
        FileUtils.cp(File.join(@tmp, 'learning.jsonl'), File.join(PWN::Migrate::BACKUP_ROOT, '20260105_000000', 'learning.jsonl'))
        result = PWN::Migrate.prune_backups(dry_run: false, expire_history: true)
        expect(result[:deleted]).to eq(['20260102_000000'])
        expect(result[:pins]).to eq(['20260101_000000'])
      end

      it 'refuses expiry without current coverage or matching credential recovery' do
        File.write(File.join(@tmp, 'pwn.yaml'), 'encrypted-current-fixture')
        result = PWN::Migrate.prune_backups(dry_run: false, expire_history: true)
        expect(result[:incomplete]).to be true
        expect(result[:deleted]).to be_empty
        File.write(File.join(PWN::Migrate::BACKUP_ROOT, '20260105_000000', 'pwn.yaml'), 'encrypted-old-fixture')
        expect(PWN::Migrate.prune_backups(dry_run: false, expire_history: true)[:error]).to match(/encrypted configuration/)
      end

      it 'refuses symlinks and held producer locks and exhausted admission' do
        File.symlink(File.join(@tmp, 'memory.json'), File.join(PWN::Migrate::BACKUP_ROOT, '20260101_000000', 'unsafe'))
        expect(PWN::Migrate.prune_backups(dry_run: false, expire_history: true)[:deleted]).to be_empty
        File.unlink(File.join(PWN::Migrate::BACKUP_ROOT, '20260101_000000', 'unsafe'))
        File.open(File.join(PWN::Migrate::BACKUP_ROOT, '.retention.lock'), 'w') do |lock|
          lock.flock(File::LOCK_EX)
          expect(PWN::Migrate.prune_backups(dry_run: false, expire_history: true)[:error]).to eq('Backup maintenance active')
        end
        expect(PWN::Migrate.prune_backups(dry_run: false, expire_history: true, admission: ->(_bytes) { false })[:deleted]).to be_empty
      end
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
      expect(result[:applied_migrations]).to eq([3, 4, 5, 6, 7, 8, 9, 10, 11])
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
      expect(result[:applied_migrations]).to eq([4, 5, 6, 7, 8, 9, 10, 11])
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
      expect(result[:applied_migrations]).to eq([5, 6, 7, 8, 9, 10, 11])
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

    it 'upgrades a schema-5 vault with ai.tui.theme without replacing a chosen color' do
      yaml = File.join(@tmp, 'pwn.yaml')
      dec = File.join(@tmp, 'pwn.yaml.decryptor')
      stale = { ai: { active: 'grok', grok: { key: 'sk-KEEP' }, tui: { theme: { assistant: 'blue' } } } }
      File.write(yaml, YAML.dump(stale).gsub(/^(\s*):/, '\1'))
      PWN::Plugins::Vault.create(file: yaml, decryptor_file: dec)
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 5))
      expect(described_class.run(fix: true, backup: false, io: io)[:applied_migrations]).to eq([6, 7, 8, 9, 10, 11])
      creds = YAML.safe_load_file(dec, symbolize_names: true)
      user = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      theme = user.dig(:ai, :tui, :theme)
      expect(theme[:assistant]).to eq('blue')
      expect(theme[:border]).to eq('black')
      expect(theme[:title]).to eq('red')
      expect(theme[:request]).to eq('white')
      expect(theme).to eq(PWN::Config.env_template.dig(:ai, :tui, :theme).merge(assistant: 'blue'))
      expect(user.dig(:ai, :grok, :key)).to eq('sk-KEEP')
      expect(described_class.run(fix: true, backup: false, io: io)[:applied_migrations]).to eq([])
      expect(PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv]).dig(:ai, :tui, :theme)).to eq(theme)
    end

    it 'preserves every configured theme role when backfilling a current-schema vault' do
      yaml = File.join(@tmp, 'pwn.yaml')
      dec = File.join(@tmp, 'pwn.yaml.decryptor')
      chosen = PWN::Config.env_template.dig(:ai, :tui, :theme).transform_values { 'blue' }
      user = PWN::Config.env_template
      user[:ai][:tui][:theme] = chosen
      File.write(yaml, YAML.dump(user))
      PWN::Plugins::Vault.create(file: yaml, decryptor_file: dec)
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: described_class::SCHEMA_VERSION))
      encrypted = File.binread(yaml)
      expect(described_class.backfill_vault(io: io)[:added]).to eq(0)
      expect(File.binread(yaml)).to eq(encrypted)
      creds = YAML.safe_load_file(dec, symbolize_names: true)
      expect(PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv]).dig(:ai, :tui, :theme)).to eq(chosen)
    end

    it 'upgrades a schema-8 vault with channel short_name without replacing from or an existing name' do
      yaml = File.join(@tmp, 'pwn.yaml')
      dec = File.join(@tmp, 'pwn.yaml.decryptor')
      stale = {
        plugins: {
          meshtastic: {
            channel: {
              active: 'LongFast',
              LongFast: { from: '!0000abcd', psk: 'AQ==' },
              Kept: { from: '!0000eeee', short_name: 'KEEP' }
            }
          }
        }
      }
      File.write(yaml, YAML.dump(stale).gsub(/^(\s*):/, '\1'))
      PWN::Plugins::Vault.create(file: yaml, decryptor_file: dec)
      File.write(File.join(@tmp, '.schema'), JSON.generate(schema: 8))
      expect(described_class.run(fix: true, backup: false, io: io)[:applied_migrations]).to eq([9, 10, 11])
      creds = YAML.safe_load_file(dec, symbolize_names: true)
      user = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      long_fast = user.dig(:plugins, :meshtastic, :channel, :LongFast)
      kept = user.dig(:plugins, :meshtastic, :channel, :Kept)
      expect(long_fast[:from]).to eq('!0000abcd')
      expect(long_fast[:psk]).to eq('AQ==')
      expect(long_fast[:short_name]).to eq('')
      expect(kept[:short_name]).to eq('KEEP')
      expect(kept[:from]).to eq('!0000eeee')
      expect(described_class.run(fix: true, backup: false, io: io)[:applied_migrations]).to eq([])
      again = PWN::Plugins::Vault.dump(file: yaml, key: creds[:key], iv: creds[:iv])
      expect(again.dig(:plugins, :meshtastic, :channel, :LongFast, :short_name)).to eq('')
      expect(again.dig(:plugins, :meshtastic, :channel, :Kept, :short_name)).to eq('KEEP')
    end

    it 'dry_run writes nothing' do
      r = PWN::Migrate.run(fix: true, backup: true, dry_run: true, io: io)
      expect(r[:dry_run]).to be true
      expect(File).not_to exist(File.join(@tmp, '.schema'))
      expect(Dir.glob(File.join(@tmp, 'backup', '*'))).to be_empty
    end
  end
end

describe PWN::Migrate, 'backup housekeeping' do
  include_context 'pwn tmp sandbox'
  let(:io) { StringIO.new }

  it 'does not snapshot or rewrite the stamp on a no-op migration' do
    File.write(File.join(@tmp, '.schema'), JSON.generate(schema: described_class::SCHEMA_VERSION))
    before = File.binread(File.join(@tmp, '.schema'))
    expect(described_class).not_to receive(:backup!)
    result = described_class.run(io: io)
    expect(result[:backup]).to be_nil
    expect(File.binread(File.join(@tmp, '.schema'))).to eq(before)
  end

  it 'retains three recovery points and unique history but prunes verified duplicate snapshots' do
    root = described_class::BACKUP_ROOT
    5.times do |i|
      dir = File.join(root, "2026010#{i + 1}_000000")
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, 'learning.jsonl'), i.zero? ? 'unique evidence' : 'same evidence')
    end
    preview = described_class.prune_backups
    expect(preview[:eligible].length).to eq(1)
    expect(Dir.children(root).length).to eq(5)
    applied = described_class.prune_backups(dry_run: false)
    expect(applied[:deleted].length).to eq(1)
    expect(File.binread(File.join(root, '20260101_000000', 'learning.jsonl'))).to eq('unique evidence')
    expect(Dir.children(root).grep(/\A\d/).length).to eq(4)
  end

  it 'publishes a verified scoped snapshot and fails closed on a copy failure' do
    File.write(File.join(@tmp, 'learning.jsonl'), 'historical evidence')
    FileUtils.mkdir_p(File.join(@tmp, 'logs'))
    File.write(File.join(@tmp, 'logs', 'debug.log'), 'not migration input')
    path = described_class.send(:backup!)
    expect(File.binread(File.join(path, 'learning.jsonl'))).to eq('historical evidence')
    expect(File).not_to exist(File.join(path, 'logs'))
    manifest = JSON.parse(File.binread(File.join(path, '.snapshot-manifest.json')))
    expect(manifest['complete']).to be(true)
    expect(manifest['files']).to have_key('learning.jsonl')
    allow(FileUtils).to receive(:cp_r).and_raise(IOError, 'copy failed')
    expect { described_class.send(:backup!) }.to raise_error(IOError, 'copy failed')
  end

  it 'rejects symlinked backup trees and exhausted admission without deleting anything' do
    root = described_class::BACKUP_ROOT
    FileUtils.mkdir_p(root)
    File.symlink(@tmp, File.join(root, '20260101_000000'))
    expect(described_class.prune_backups(dry_run: false)[:incomplete]).to be(true)
    File.unlink(File.join(root, '20260101_000000'))
    4.times do |i|
      dir = File.join(root, "2026010#{i + 1}_000000")
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, 'state'), 'same')
    end
    result = described_class.prune_backups(dry_run: false, admission: ->(_bytes) { false })
    expect(result[:incomplete]).to be(true)
    expect(result[:deleted]).to eq([])
    expect(Dir.children(root).grep(/\A\d/).length).to eq(4)
  end

  it 'skips backups for fix mode when schema, files and vault have no drift' do
    File.write(File.join(@tmp, '.schema'), JSON.generate(schema: described_class::SCHEMA_VERSION))
    allow(described_class).to receive(:vault_drift).and_return({ missing: [] })
    allow(described_class).to receive(:status).and_return({ schema_installed: described_class::SCHEMA_VERSION, schema_current: described_class::SCHEMA_VERSION, incompatible: [], pwn_version: 'test' })
    expect(described_class).not_to receive(:backup!)
    expect(described_class.run(fix: true, io: io)[:backup]).to be_nil
  end
end
