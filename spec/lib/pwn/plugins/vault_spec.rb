# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Vault, 'concurrent loot storage' do
  include_context 'pwn tmp sandbox'

  it 'keeps one master key when separate engagements are initialized concurrently' do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(described_class).to receive(:note_mission_loot)
    entered = Queue.new
    release = Queue.new
    allow(OpenSSL::Random).to receive(:random_bytes).and_wrap_original do |method, length|
      if length == 32 && Thread.current[:vault_first_writer]
        entered << true
        release.pop
      end
      method.call(length)
    end
    first = Thread.new do
      Thread.current[:vault_first_writer] = true
      described_class.store(engagement: 'first', label: 'first', secret: 'first-fixture')
    end
    Timeout.timeout(5) { entered.pop }
    second = Thread.new { described_class.store(engagement: 'second', label: 'second', secret: 'second-fixture') }
    second.join(0.5)
    release << true
    Timeout.timeout(5) { [first, second].each(&:value) }
    expect(described_class.fetch(label: 'first', engagement: 'first')).to eq('first-fixture')
    expect(described_class.fetch(label: 'second', engagement: 'second')).to eq('second-fixture')
  ensure
    release << true if release
    [first, second].compact.each { |thread| thread.kill.join if thread.alive? }
  end

  it 'retains both records when another writer arrives during encryption' do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(described_class).to receive(:note_mission_loot)
    entered = Queue.new
    release = Queue.new
    allow(described_class).to receive(:encrypt_secret).and_wrap_original do |method, opts|
      if opts[:secret] == 'first-fixture'
        entered << true
        release.pop
      end
      method.call(opts)
    end
    first = Thread.new { described_class.store(label: 'first', secret: 'first-fixture') }
    Timeout.timeout(5) { entered.pop }
    second = Thread.new { described_class.store(label: 'second', secret: 'second-fixture') }
    second.join(0.5)
    release << true
    Timeout.timeout(5) { [first, second].each(&:value) }
    expect(described_class.query.map { |row| row[:label] }).to contain_exactly('first', 'second')
    expect(described_class.fetch(label: 'first')).to eq('first-fixture')
    expect(described_class.fetch(label: 'second')).to eq('second-fixture')
  ensure
    release << true if release
    [first, second].compact.each { |thread| thread.kill.join if thread.alive? }
  end
end

describe PWN::Plugins::Vault do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Vault
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Vault
    expect(help_response).to respond_to :help
  end

  it 'expands vault tokens and redacts stored secrets' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      described_class.store(label: 'api', secret: 's3cret-value')
      expect(described_class.fetch(label: 'api')).to eq('s3cret-value')
      expect(described_class.expand(text: 'tok={{vault:api}}')).to include('s3cret-value')
      expect(described_class.redact(text: 'tok=s3cret-value')).to include('{{vault:api}}')
    end
  end

  it 'stores engagement-scoped creds with provenance and offers them for auth' do
    Dir.mktmpdir('pwn-loot-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      row = described_class.store(
        secret: 'hunter2',
        username: 'admin',
        host: 'app.example.test',
        service: 'http',
        kind: 'password',
        source: 'recon',
        where: 'https://app.example.test/.env',
        finding_id: 'f00bar',
        engagement: 'lab'
      )
      expect(row[:engagement]).to eq('lab')
      expect(row[:finding_id]).to eq('f00bar')
      expect(row[:where]).to include('.env')
      hits = described_class.query(host: 'app.example.test', engagement: 'lab')
      expect(hits.first[:username]).to eq('admin')
      expect(hits.first[:finding_id]).to eq('f00bar')
      offered = described_class.offer(host: 'app.example.test', service: 'http', engagement: 'lab')
      expect(offered.first[:username]).to eq('admin')
      expect(offered.first[:secret]).to eq('hunter2')
    end
  end

  it 'ingests recon banner creds into the loot store' do
    Dir.mktmpdir('pwn-loot-ingest-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      described_class.ingest(
        text: "username=admin\npassword=hunter2\n",
        host: 'app.example.test',
        source: 'recon',
        where: 'banner:22',
        engagement: 'lab'
      )
      offered = described_class.offer(host: 'app.example.test', engagement: 'lab')
      expect(offered.first[:secret]).to eq('hunter2')
    end
  end
end
