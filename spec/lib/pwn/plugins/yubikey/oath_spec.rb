# frozen_string_literal: true

require 'spec_helper'

# Independent wire fixtures: Yubico OATH protocol SELECT/LIST/CALCULATE,
# RFC 6238 SHA1 time 59 truncation (0x41397eea => 94287082).
describe 'PWN::Plugins::YubiKey::OATH native protocol' do
  let(:oath) { PWN::Plugins::YubiKey::OATH }
  let(:wire_class) do
    Class.new do
      attr_reader :seen

      def initialize(steps)
        @steps = steps.dup
        @seen = []
      end

      def descriptor
        { protocol: :apdu }
      end

      def exchange(opts = {})
        raise 'wrong transport' unless opts[:protocol] == :apdu

        actual = opts[:data].unpack1('H*')
        @seen << actual
        expected, response = @steps.shift
        raise "unexpected APDU #{actual}" unless expected && (expected.is_a?(Regexp) ? expected.match?(actual) : actual == expected)

        response.respond_to?(:call) ? response.call(opts[:data]) : [response].pack('H*')
      end

      def complete?
        @steps.empty?
      end
    end
  end
  let(:select) { %w[00a4040007a0000005272101 7903050800710831323334353637389000] }

  before do
    require 'pwn/plugins/yubikey/protocol'
    require 'pwn/plugins/yubikey/oath'
  end

  it 'calculates only the unique exact account with RFC 6238 leading digits' do
    wire = wire_class.new([
                            select,
                            %w[00a1000000 7205216163637472062161636374329000],
                            %w[00a200011071046163637474080000000000000001 76050841397eea9000]
                          ])
    expect(oath.code(connection: wire, account: 'acct', timestamp: 59, confirm: true)).to eq('94287082')
    expect(wire.complete?).to be(true)
  end

  it 'performs mutual authentication exactly once before listing a locked application' do
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('ABCDEFGH')
    wire = wire_class.new([
                            [select[0], '790305080071083132333435363738740861626364656667689000'],
                            %w[00a30000207514db45e133f47e3e7a338c965f23bb02012cc4330a74084142434445464748 751496aa98f40d9ee3dc4b3c243ebd3dc8e53fcf4ef59000],
                            %w[00a1000000 720521616363749000]
                          ])
    expect(oath.execute(connection: wire, args: %w[accounts list], password: 'synthetic oath', confirm: true)).to include(include(id: 'acct', period: 30))
    expect(wire.complete?).to be(true)
  end

  it 'requires explicit consent before any code operation or secret-provider invocation' do
    wire = wire_class.new([])
    provider = ->(_name) { raise 'must not ask for a secret' }
    expect { oath.code(connection: wire, account: 'acct', secret_provider: provider) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(wire.seen).to be_empty
  end

  it 'returns leading zeroes for HOTP and uses the empty challenge' do
    wire = wire_class.new([select, %w[00a1000000 720511616363749000], %w[00a20001087104616363747400 760506000000019000]])
    expect(oath.code(connection: wire, account: 'acct', confirm: true)).to eq('000001')
    expect(wire.complete?).to be(true)
  end

  it 'does not calculate a substring or Unicode-normalized account identity' do
    ['acc', "a\u0301", ' acct'].each do |account|
      wire = wire_class.new([select, %w[00a1000000 720521616363749000]])
      expect { oath.code(connection: wire, account: account, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /exact/)
      expect(wire.complete?).to be(true)
    end
  end

  it 'does not retry or delete on a device memory error' do
    wire = wire_class.new([select, %w[00a1000000 6581]])
    expect { oath.code(connection: wire, account: 'acct', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Error)
    expect(wire.complete?).to be(true)
  end

  def apdu(ins, payload = ''.b, param1: 0, param2: 0)
    ([0, ins, param1, param2] + (payload.empty? ? [] : [payload.bytesize])).pack('C*').unpack1('H*') + payload.unpack1('H*')
  end

  def field(tag, value)
    [tag, value.bytesize].pack('CC') + value.b
  end

  it 'imports a raw secret with explicit overwrite consent and reads back the exact ID' do
    payload = field(0x71, 'acct') + field(0x73, "\x21\x0612345678901234567890")
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720521616363749000]])
    result = oath.execute(connection: wire, args: %w[accounts add acct], secret: '12345678901234567890', confirm: true)
    expect(result).to include(id: 'acct', verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'validates URI metadata without repairing conflicting issuers or malformed secrets' do
    parsed = oath.parse_uri(uri: 'otpauth://totp/Example%3Aalice?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60')
    expect(parsed).to include(name: 'alice', issuer: 'Example', secret: '1234567890', algorithm: :sha256, digits: 8, period: 60)
    expect { oath.parse_uri(uri: 'otpauth://totp/A:x?secret=MY&issuer=B') }.to raise_error(ArgumentError)
    expect { oath.parse_uri(uri: 'otpauth://totp/x?secret=MZ') }.to raise_error(ArgumentError)
  end

  it 'refuses invalid public import arguments before authentication or prompting' do
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[accounts add acct --digits 9], secret_provider: ->(_key) { raise 'prompted' }, confirm: true) }.to raise_error(ArgumentError)
    expect(wire.seen).to be_empty
  end

  it 'renames exact IDs without deleting either account and verifies the new name' do
    payload = field(0x71, 'acct') + field(0x71, 'new')
    wire = wire_class.new([select, %w[00a1000000 720521616363749000], [apdu(5, payload), '9000'], %w[00a1000000 7204216e65779000]])
    expect(oath.execute(connection: wire, args: %w[accounts rename acct new], confirm: true)).to include(id: 'new', verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'deletes only the exact ID and verifies absence' do
    wire = wire_class.new([select, %w[00a1000000 720521616363749000], %w[0002000006710461636374 9000], %w[00a1000000 9000]])
    expect(oath.execute(connection: wire, args: %w[accounts delete acct], confirm: true)).to include(deleted: 'acct', verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'sets an access key with PBKDF2/HMAC and reads back password protection' do
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('ABCDEFGH')
    payload = field(0x73, ['21ed78608d6e1b6954df83a2044711b48f'].pack('H*')) + field(0x74, 'ABCDEFGH') + field(0x75, ['96aa98f40d9ee3dc4b3c243ebd3dc8e53fcf4ef5'].pack('H*'))
    locked_select = [select[0], '790305080071083132333435363738740861626364656667689000']
    wire = wire_class.new([select, [apdu(3, payload), '9000'], locked_select])
    expect(oath.execute(connection: wire, args: %w[access change], new_password: 'synthetic oath', confirm: true)).to include(locked: true, verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'clears access protection only after mutual authentication' do
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('ABCDEFGH')
    locked_select = [select[0], '790305080071083132333435363738740861626364656667689000']
    wire = wire_class.new([locked_select, %w[00a30000207514db45e133f47e3e7a338c965f23bb02012cc4330a74084142434445464748 751496aa98f40d9ee3dc4b3c243ebd3dc8e53fcf4ef59000], %w[00030000027300 9000], select])
    expect(oath.execute(connection: wire, args: %w[access change --clear], password: 'synthetic oath', confirm: true)).to include(locked: false, verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'requires an explicit encrypted-cache handoff and verifies remember and forget effects' do
    cache = Class.new do
      def encrypted? = true
      def store(device_id:, access_key:) = @record = [device_id, access_key]
      def fetch(device_id:) = @record && @record[0] == device_id ? @record[1] : nil

      def delete(device_id:)
        @record = nil if @record && @record[0] == device_id
      end
    end.new
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('ABCDEFGH')
    locked_select = [select[0], '790305080071083132333435363738740861626364656667689000']
    wire = wire_class.new([locked_select, %w[00a30000207514db45e133f47e3e7a338c965f23bb02012cc4330a74084142434445464748 751496aa98f40d9ee3dc4b3c243ebd3dc8e53fcf4ef59000]])
    result = oath.execute(connection: wire, args: %w[access remember], password: 'synthetic oath', encrypted_cache: cache, confirm: true)
    expect(result).to include(cache_handoff: true, verified: true)
    wire = wire_class.new([select])
    expect(oath.execute(connection: wire, args: %w[access forget], encrypted_cache: cache, confirm: true)).to include(forgotten: true, verified: true)
    expect(wire.complete?).to be(true)
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[access remember], password: 'synthetic oath', confirm: true) }.to raise_error(ArgumentError, /encrypted_cache/)
    expect(wire.seen).to be_empty
  end

  it 'resets with DEAD and verifies new salt plus empty inventory' do
    wire = wire_class.new([select, %w[0004dead00 9000], [select[0], '7903050800710838373635343332319000'], %w[00a1000000 9000]])
    expect(oath.execute(connection: wire, args: ['reset'], confirm: true)).to include(reset: true, verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'calculates all TOTP codes but leaves HOTP and touch records untriggered' do
    response = field(0x71, 'acct') + field(0x76, ['0600000001'].pack('H*')) + field(0x71, 'hotp') + field(0x77, "\x06") + field(0x71, 'touch') + field(0x7c, "\x06")
    wire = wire_class.new([select, [apdu(0xa4, field(0x74, "#{"\x00" * 7}\x01"), param2: 1), "#{response.unpack1('H*')}9000"]])
    values = oath.calculate_all(connection: wire, timestamp: 59, confirm: true)
    expect(values.map { |record| record[:code]&.fetch(:value) }).to eq(['000001', nil, nil])
    expect(values.map { |record| record[:oath_type] }).to eq(%i[totp hotp totp])
    expect(wire.complete?).to be(true)
  end

  it 'exposes raw HMAC calculation without treating it as a numeric code' do
    payload = field(0x71, 'acct') + field(0x74, 'challenge')
    wire = wire_class.new([select, %w[00a1000000 720521616363749000], [apdu(0xa2, payload), "751506#{'ab' * 20}9000"]])
    expect(oath.calculate(connection: wire, account: 'acct', challenge: 'challenge', confirm: true)).to eq(['ab' * 20].pack('H*'))
    expect(wire.complete?).to be(true)
  end

  it 'imports an in-memory PSKC container without skipping invalid records' do
    xml = '<KeyContainer xmlns="urn:ietf:params:xml:ns:keyprov:pskc" Version="1.0"><KeyPackage><Key Id="acct" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp"><AlgorithmParameters><ResponseFormat Length="6" Encoding="DECIMAL"/></AlgorithmParameters><Data><Secret><PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</PlainValue></Secret></Data></Key></KeyPackage></KeyContainer>'
    payload = field(0x71, 'acct') + field(0x73, "\x21\x0612345678901234567890")
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720521616363749000]])
    expect(oath.execute(connection: wire, args: %w[accounts import], pskc: xml, confirm: true)).to include(include(id: 'acct', verified: true))
    expect(wire.complete?).to be(true)
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[accounts import], pskc: xml.sub('pskc:totp', 'pskc:unknown'), confirm: true) }.to raise_error(ArgumentError)
    expect(wire.seen).to be_empty
  end

  it 'unwraps a PSKC AES key-wrap secret using the RFC 3394 published vector' do
    xml = '<KeyContainer xmlns="urn:ietf:params:xml:ns:keyprov:pskc" xmlns:x="http://www.w3.org/2001/04/xmlenc#" Version="1.0"><KeyPackage><Key Id="acct" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp"><Data><Secret><EncryptedValue><x:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><x:CipherData><x:CipherValue>H6aLCoEStEeu80vY+1p7gp0+hiNx0s/l</x:CipherValue></x:CipherData></EncryptedValue></Secret><Counter><PlainValue>0</PlainValue></Counter></Data></Key></KeyPackage></KeyContainer>'
    secret = ['00112233445566778899aabbccddeeff'].pack('H*')
    payload = field(0x71, 'acct') + field(0x73, "\x11\x06".b + secret)
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720511616363749000]])
    key = ['000102030405060708090a0b0c0d0e0f'].pack('H*')
    expect(oath.execute(connection: wire, args: %w[accounts import], pskc: xml, pskc_key: key, confirm: true)).to include(include(id: 'acct', verified: true))
    expect(wire.complete?).to be(true)
  end

  it 'rejects malformed XML and an invalid later import record before any APDU' do
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[accounts import], pskc: '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///none">]><a/>', confirm: true) }.to raise_error(ArgumentError)
    expect { oath.execute(connection: wire, args: %w[accounts import], credentials: [{ name: 'one', secret: 'x' * 20 }, { name: 'two', secret: 'x' }], confirm: true) }.to raise_error(ArgumentError)
    expect(wire.seen).to be_empty
  end

  it 'imports authenticated AES-CBC PSKC with PBKDF2 and rejects a bad MAC before I/O' do
    # Independently encrypted with Python cryptography AES-CBC / hashlib PBKDF2.
    xml = <<~XML
      <KeyContainer xmlns="urn:ietf:params:xml:ns:keyprov:pskc" xmlns:x="http://www.w3.org/2001/04/xmlenc#" xmlns:k="http://www.w3.org/2009/xmlenc11#" Version="1.0">
        <EncryptionKey><k:DerivedKey><k:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#pbkdf2"><k:PBKDF2-params><k:Salt><k:Specified>MDEyMzQ1Njc4OWFiY2RlZg==</k:Specified></k:Salt><k:IterationCount>1000</k:IterationCount><k:KeyLength>16</k:KeyLength><k:PRF Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/></k:PBKDF2-params></k:KeyDerivationMethod></k:DerivedKey></EncryptionKey>
        <MACMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"><MACKey><x:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><x:CipherData><x:CipherValue>SkpKSkpKSkpKSkpKSkpKSmxrtkfn/Z3m3XbUoFWKDNZhAjYTOVdo4oaO5plAkray</x:CipherValue></x:CipherData></MACKey></MACMethod>
        <KeyPackage><Key Id="acct" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp"><Data><Secret><EncryptedValue><x:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><x:CipherData><x:CipherValue>SUlJSUlJSUlJSUlJSUlJSdb4gWWgYtJgOxUEkeaFZQt1DfO02SIT0Ze547y+hMFy</x:CipherValue></x:CipherData></EncryptedValue><ValueMAC>RO0CeBbbOXmD5PARLx3KS5LiCdVI9dgZgoUMW7FjX3A=</ValueMAC></Secret></Data></Key></KeyPackage>
      </KeyContainer>
    XML
    payload = field(0x71, 'acct') + field(0x73, "\x21\x0612345678901234567890")
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720521616363749000]])
    expect(oath.execute(connection: wire, args: %w[accounts import], pskc: xml, pskc_password: 'synthetic PSKC', confirm: true)).to include(include(verified: true))
    expect(wire.complete?).to be(true)
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[accounts import], pskc: xml.sub('RO0Ce', 'AO0Ce'), pskc_password: 'synthetic PSKC', confirm: true) }.to raise_error(ArgumentError, /integrity/)
    expect(wire.seen).to be_empty
  end

  it 'uses OATH SEND REMAINING with zero Le across fragmented LIST responses' do
    wire = wire_class.new([select, %w[00a1000000 72056104], %w[00a5000000 21616363749000]])
    expect(oath.execute(connection: wire, args: %w[accounts list])).to include(include(id: 'acct'))
    expect(wire.complete?).to be(true)
  end

  it 'matches independent RFC 6238 SHA1, SHA256 and SHA512 truncation vectors' do
    [[1, 59, '41397eea', '94287082'], [1, 1_111_111_109, '3610f84c', '07081804'], [2, 59, '2c78e04e', '46119246'], [3, 59, '1d3f6530', '90693936']].each do |algorithm, time, truncated, value|
      inventory = "#{field(0x72, "#{[0x20 | algorithm].pack('C')}acct").unpack1('H*')}9000"
      payload = field(0x71, 'acct') + field(0x74, [time / 30].pack('Q>'))
      wire = wire_class.new([select, ['00a1000000', inventory], [apdu(0xa2, payload, param2: 1), "760508#{truncated}9000"]])
      expect(oath.code(connection: wire, account: 'acct', timestamp: time, confirm: true)).to eq(value)
      expect(wire.complete?).to be(true)
    end
  end

  it 'uses the nonstandard period encoded in the exact credential ID' do
    payload = field(0x71, '60/acct') + field(0x74, [1].pack('Q>'))
    wire = wire_class.new([select, ['00a1000000', "#{field(0x72, "\x2260/acct").unpack1('H*')}9000"], [apdu(0xa2, payload, param2: 1), '760506000000019000']])
    expect(oath.code(connection: wire, account: '60/acct', timestamp: 119, confirm: true)).to eq('000001')
    expect(wire.complete?).to be(true)
  end

  it 'imports HOTP touch/counter attributes using the property pair rather than a TLV' do
    secret = 'x' * 20
    payload = "#{field(0x71, 'acct')}#{field(0x73, "\x12\x07#{secret}")}\x78\x02#{field(0x7a, [7].pack('N'))}"
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720512616363749000]])
    expect(oath.execute(connection: wire, args: %w[accounts add acct --oath-type HOTP --algorithm SHA256 --digits 7 --counter 7 --touch], secret: secret, confirm: true)).to include(oath_type: :hotp, algorithm: :sha256)
    expect(wire.complete?).to be(true)
  end

  it 'refuses overwrite, unsupported touch and unsupported rename without mutation' do
    wire = wire_class.new([select, %w[00a1000000 720521616363749000]])
    expect { oath.execute(connection: wire, args: %w[accounts add acct], secret: 'x' * 20, confirm: true) }.to raise_error(ArgumentError, /overwrite/)
    old = [select[0], '7903040205710831323334353637389000']
    wire = wire_class.new([old])
    expect { oath.execute(connection: wire, args: %w[accounts add acct --touch], secret: 'x' * 20, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Error, /unsupported/)
    wire = wire_class.new([old])
    expect { oath.execute(connection: wire, args: %w[accounts rename acct new], confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Error, /unsupported/)
    expect(wire.complete?).to be(true)
  end

  it 'fails mutual authentication without invoking list, fallback credentials or repair' do
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('ABCDEFGH')
    wire = wire_class.new([[select[0], '790305080071083132333435363738740861626364656667689000'], ['00a30000207514db45e133f47e3e7a338c965f23bb02012cc4330a74084142434445464748', "7514#{'00' * 20}9000"]])
    expect { oath.code(connection: wire, account: 'acct', password: 'synthetic oath', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /authentication/)
    expect(wire.complete?).to be(true)
  end

  it 'rejects duplicate inventory identities and malformed code responses' do
    wire = wire_class.new([select, %w[00a1000000 72052161636374720521616363749000]])
    expect { oath.code(connection: wire, account: 'acct', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /Duplicate/)
    ["\x06\x01", "\x09\x00\x00\x00\x01"].each do |truncated|
      wire = wire_class.new([select, %w[00a1000000 720511616363749000], ['00a20001087104616363747400', "#{field(0x76, truncated).unpack1('H*')}9000"]])
      expect { oath.code(connection: wire, account: 'acct', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /Malformed/)
      expect(wire.complete?).to be(true)
    end
  end

  it 'preserves URI touch policy and rejects nonboolean controls before I/O' do
    payload = "#{field(0x71, 'acct')}#{field(0x73, "\x21\x06#{'1234567890'.ljust(14, "\x00")}")}\x78\x02"
    wire = wire_class.new([select, %w[00a1000000 9000], [apdu(1, payload), '9000'], %w[00a1000000 720521616363749000]])
    expect(oath.execute(connection: wire, args: %w[accounts uri --touch], uri: 'otpauth://totp/acct?secret=GEZDGNBVGY3TQOJQ', confirm: true)).to include(verified: true)
    expect(wire.complete?).to be(true)
    wire = wire_class.new([])
    expect { oath.execute(connection: wire, args: %w[accounts add acct], generate: 'false', confirm: true) }.to raise_error(ArgumentError, /boolean/)
    expect(wire.seen).to be_empty
  end

  it 'supports all-account command routing without incrementing HOTP counters' do
    response = field(0x71, 'hotp') + field(0x77, "\x06")
    wire = wire_class.new([select, [apdu(0xa4, field(0x74, [1].pack('Q>')), param2: 1), "#{response.unpack1('H*')}9000"]])
    expect(oath.execute(connection: wire, args: %w[accounts code], timestamp: 59, confirm: true)).to include(include(oath_type: :hotp, code: nil))
    expect(wire.complete?).to be(true)
  end

  it 'does not treat nonboolean direct cache controls as consent to a cache handoff' do
    wire = wire_class.new([])
    expect { oath.code(connection: wire, account: 'acct', confirm: true, remember: 'false') }.to raise_error(ArgumentError, /boolean/)
    expect(wire.seen).to be_empty
  end

  it 'reads OATH version and protection state without trying an access password' do
    wire = wire_class.new([select])
    expect(oath.execute(connection: wire, args: ['info'])).to include(version: [5, 8, 0], locked: false)
    expect(wire.complete?).to be(true)
  end

  it 'propagates a calculation timeout without retry or hidden mutation' do
    failure = ->(_packet) { raise PWN::Plugins::YubiKey::TimeoutError, 'synthetic cancelled I/O' }
    wire = wire_class.new([select, %w[00a1000000 720511616363749000], ['00a20001087104616363747400', failure]])
    expect { oath.code(connection: wire, account: 'acct', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(wire.complete?).to be(true)
    expect(wire.seen.length).to eq(3)
  end

  it 'documents every public API and secret option in actual help output' do
    expect { oath.help }.to output(/\.execute\(.*secret_base32:.*encrypted_cache:.*\.operations.*\.parse_uri.*\.code\(.*account:.*\.calculate\(.*challenge:.*\.calculate_all\(.*\.authors/m).to_stdout
  end

  it 'keeps help local and does not claim groups as implemented leaves' do
    wire = wire_class.new([])
    expect(oath.execute(connection: wire, args: ['accounts'])).to include(application: :oath)
    expect(oath.operations).not_to include('accounts', 'access')
    expect(wire.seen).to be_empty
  end
end
