# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Vault, 'loot corruption safety' do
  before do
    @root = Dir.mktmpdir('vault-loot-safety-')
    allow(Dir).to receive(:home).and_return(@root)
    allow(described_class).to receive(:note_mission_loot)
    @device = double('offline YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge]) }
    @path = File.join(@root, '.pwn', 'engagements', 'default', 'loot.json')
    @legacy_path = File.join(@root, '.pwn', 'vault-secrets.json')
    FileUtils.mkdir_p(File.dirname(@path))
  end

  after do
    FileUtils.remove_entry(@root)
  end

  {
    'malformed JSON' => '{"PRIVATE_PARSE_MARKER":',
    'nonmapping root' => '[]',
    'nonarray records' => '{"records": {}}',
    'null records' => '{"records": null}',
    'nonmapping row' => '{"version": 2, "records": [false]}',
    'missing secret' => '{"version": 2, "records": [{"label": "protected"}]}',
    'nonmapping secret' => '{"version": 2, "records": [{"label": "protected", "secret": false}]}',
    'nonstring label' => '{"version": 2, "records": [{"label": 123, "secret": {}}]}',
    'invalid legacy row' => '{"protected": false}'
  }.each do |description, damaged|
    it "refuses #{description} before choosing a store backend", :aggregate_failures do
      described_class.store(label: 'protected', secret: 'original-fixture', yubikey: {})
      File.binwrite(@path, damaged)
      expect do
        described_class.store(label: 'protected', secret: 'replacement-fixture')
      end.to raise_error(IOError, /loot store/)
      expect(File.binread(@path)).to eq(damaged)
      expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
    end
  end

  it 'does not overwrite corrupt records even with an explicit hardware destination' do
    damaged = '{"records": [null]}'
    File.write(@path, damaged)
    expect(@device).not_to receive(:challenge_response)
    expect { described_class.store(label: 'protected', secret: 'fixture', yubikey: {}) }.to raise_error(IOError, /loot store/)
    expect(File.binread(@path)).to eq(damaged)
  end

  it 'rejects incomplete or unknown hardware envelopes rather than replacing them with software encryption', :aggregate_failures do
    described_class.store(label: 'protected', secret: 'original-fixture', yubikey: {})
    original = JSON.parse(File.read(@path))
    [nil, 'unknown-kdf'].each do |invalid|
      damaged = Marshal.load(Marshal.dump(original))
      damaged['records'].first['secret']['kdf'] = invalid
      File.write(@path, JSON.generate(damaged))
      expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, /loot store/)
      expect(JSON.parse(File.read(@path))).to eq(damaged)
      expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
    end
    original['records'].first['secret']['yubikey'] = nil
    File.write(@path, JSON.generate(original))
    expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, /loot store/)
    expect(JSON.parse(File.read(@path))).to eq(original)
  end

  it 'reports unreadable existing stores without treating them as absent', :aggregate_failures do
    File.write(@path, '{"records": []}')
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with(@path).and_raise(Errno::EACCES, 'PRIVATE_PARSE_MARKER')
    expect { described_class.store(label: 'protected', secret: 'fixture') }.to raise_error(IOError, /loot store/)
    expect(File.binread(@path)).to eq('{"records": []}')
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'does not treat a nonregular existing store as absent' do
    Dir.mkdir(@path)
    expect { described_class.query }.to raise_error(IOError, /loot store/)
    expect { described_class.store(label: 'protected', secret: 'fixture') }.to raise_error(IOError, /loot store/)
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'fails closed on corrupt legacy stores before creating engagement records' do
    File.write(@legacy_path, '{"PRIVATE_PARSE_MARKER":')
    expect { described_class.store(label: 'protected', secret: 'fixture') }.to raise_error(IOError, /loot store/)
    expect(File).not_to exist(@path)
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'surfaces safe diagnostics on every read-only parser path instead of silently hiding records' do
    File.write(@path, '{"PRIVATE_PARSE_MARKER":')
    queries = [
      -> { described_class.query },
      -> { described_class.fetch(label: 'protected', engagement: 'default') },
      -> { described_class.fetch(label: 'protected') },
      -> { described_class.offer },
      -> { described_class.expand(text: '{{vault:protected}}') },
      -> { described_class.redact(text: 'fixture') }
    ]
    queries.each do |query|
      expect(&query).to raise_error(IOError, /loot store/) do |error|
        expect(error.message).to include(@path)
        expect(error.message).not_to include('PRIVATE_PARSE_MARKER')
        expect(error.cause).to be_nil
      end
    end
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'preserves absent and empty stores as empty collections' do
    expect(described_class.query).to eq([])
    expect(described_class.fetch(label: 'absent')).to be_nil
    File.write(@path, JSON.generate(version: 2, records: []))
    File.write(@legacy_path, '{}')
    expect(described_class.query).to eq([])
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'reads a legacy label named records without mistaking its ciphertext for a modern collection' do
    secret = described_class.send(:encrypt_secret, secret: 'records-fixture')
    original = JSON.generate(records: secret)
    File.write(@legacy_path, original)
    expect(described_class.fetch(label: 'records')).to eq('records-fixture')
    expect(described_class.query).to contain_exactly(label: 'records', engagement: 'default', host: '', source: 'legacy', has_secret: true)
    described_class.store(label: 'hardware', secret: 'hardware-fixture', yubikey: {})
    expect(described_class.fetch(label: 'records', engagement: 'default')).to eq('records-fixture')
    expect(File.binread(@legacy_path)).to eq(original)
  end

  it 'rejects a versioned collection with a ciphertext Hash instead of a records array' do
    secret = described_class.send(:encrypt_secret, secret: 'fixture', yubikey: {})
    damaged = JSON.generate(version: 2, records: secret)
    File.write(@path, damaged)
    expect(@device).not_to receive(:challenge_response)
    expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, /loot store/)
    expect(File.binread(@path)).to eq(damaged)
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  %i[legacy hardware].each do |backend|
    it "normalizes inline #{backend} ciphertext while preserving loot metadata and protection" do
      access = backend == :hardware ? { yubikey: {} } : {}
      secret = described_class.send(:encrypt_secret, access.merge(secret: 'flat-fixture'))
      metadata = {
        id: 'fixture-id', label: 'flat', kind: 'password', engagement: 'default', host: 'login.example.test',
        service: 'ssh', username: 'fixture-user', source: 'legacy', where: '/fixture/path',
        finding_id: 'fixture-finding', at: '2026-01-01T00:00:00Z'
      }
      original = JSON.generate(version: 2, records: [secret.merge(metadata)])
      File.write(@path, original)
      expect(described_class.fetch(label: 'flat')).to eq('flat-fixture')
      expect(described_class.query).to contain_exactly(metadata.merge(has_secret: true))
      expect(described_class.offer(host: metadata[:host]).first[:secret]).to eq('flat-fixture')
      expect(described_class.expand(text: '{{vault:flat}}')).to eq('flat-fixture')
      expect(described_class.redact(text: 'flat-fixture')).to eq('{{vault:flat}}')
      expect(File.binread(@path)).to eq(original)

      described_class.store(label: 'other', secret: 'other-fixture', yubikey: {})
      saved = JSON.parse(File.read(@path))['records'].find { |row| row['label'] == 'flat' }
      expect(saved).to eq(JSON.parse(JSON.generate(metadata.merge(secret: secret))))
      described_class.store(label: 'flat', secret: 'replacement-fixture')
      expect(described_class.fetch(label: 'flat')).to eq('replacement-fixture')
      saved_secret = JSON.parse(File.read(@path))['records'].find { |row| row['label'] == 'flat' }['secret']
      if backend == :hardware
        expect(saved_secret['kdf']).to eq(described_class::YUBIKEY_KDF)
        expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
      else
        expect(saved_secret.keys).to contain_exactly('iv', 'ct', 'tag')
      end
    end
  end

  {
    'unknown KDF' => { 'kdf' => 'unknown-kdf' },
    'null KDF' => { 'kdf' => nil },
    'invalid hardware metadata' => { 'yubikey' => false },
    'runtime hardware options' => { 'yubikey' => { 'slot' => 2, 'challenge' => 'fixture', 'ykman' => '/untrusted/backend' } },
    'explicit null secret' => { 'secret' => nil },
    'explicit false secret' => { 'secret' => false }
  }.each do |description, changes|
    it "rejects inline ciphertext with #{description} instead of selecting software encryption" do
      secret = described_class.send(:encrypt_secret, secret: 'original-fixture', yubikey: {})
      damaged = JSON.generate(version: 2, records: [secret.merge('label' => 'protected').merge(changes)])
      File.write(@path, damaged)
      expect(@device).not_to receive(:challenge_response)
      expect { described_class.fetch(label: 'protected') }.to raise_error(IOError, /loot store/)
      expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, /loot store/)
      expect(File.binread(@path)).to eq(damaged)
      expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
    end
  end

  [1.0, 2.0].each do |slot|
    %i[inline nested].each do |shape|
      it "rejects float hardware slot #{slot} in #{shape} loot envelopes before selecting a backend" do
        secret = described_class.send(:encrypt_secret, secret: 'original-fixture', yubikey: {})
        secret['yubikey']['slot'] = slot
        row = shape == :inline ? secret.merge(label: 'protected') : { label: 'protected', secret: secret }
        damaged = JSON.generate(version: 2, records: [row])
        File.write(@path, damaged)
        expect(@device).not_to receive(:challenge_response)
        expect { described_class.query }.to raise_error(IOError, /loot store/)
        expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, /loot store/)
        expect(File.binread(@path)).to eq(damaged)
        expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
      end
    end
  end

  it 'retains inline hardware ciphertext when the device is unavailable during replacement' do
    secret = described_class.send(:encrypt_secret, secret: 'original-fixture', yubikey: {})
    original = JSON.generate(version: 2, records: [secret.merge(label: 'protected')])
    File.write(@path, original)
    allow(@device).to receive(:challenge_response).and_raise(IOError, 'Device unavailable')
    expect { described_class.store(label: 'protected', secret: 'replacement-fixture') }.to raise_error(IOError, 'Device unavailable')
    expect(File.binread(@path)).to eq(original)
    expect(File).not_to exist(File.join(@root, '.pwn-vault.key'))
  end

  it 'reads valid legacy label maps and preserves them when adding modern records' do
    key = 'k' * 32
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    cipher.auth_data = 'pwn-vault'
    ct = cipher.update('legacy-fixture') + cipher.final
    secret = { iv: Base64.strict_encode64(iv), ct: Base64.strict_encode64(ct), tag: Base64.strict_encode64(cipher.auth_tag) }
    File.open(File.join(@root, '.pwn-vault.key'), File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(key) }
    File.write(@legacy_path, JSON.generate(legacy: secret))
    expect(described_class.fetch(label: 'legacy')).to eq('legacy-fixture')
    described_class.store(label: 'hardware', secret: 'hardware-fixture', yubikey: {})
    expect(described_class.query.map { |row| row[:label] }).to include('legacy', 'hardware')
    expect(described_class.fetch(label: 'legacy', engagement: 'default')).to eq('legacy-fixture')
    expect(described_class.fetch(label: 'hardware', engagement: 'default')).to eq('hardware-fixture')
    expect(JSON.parse(File.read(@legacy_path), symbolize_names: true)).to eq(legacy: secret)
  end
end
