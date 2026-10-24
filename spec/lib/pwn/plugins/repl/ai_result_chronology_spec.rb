# frozen_string_literal: true

require 'spec_helper'
require 'open3'

describe 'menu result chronology' do
  let(:repl) { PWN::Plugins::REPL }

  def local_stamp(value)
    Time.iso8601(value).getlocal.strftime('%Y-%m-%d %H:%M:%S%z')
  end

  it 'uses local seasonal offsets for every recognized field and representation without mutating sources' do
    # Child-only TZ avoids racing suite threads; parent ENV never changes.
    script = <<~RUBY
      require 'pwn'
      require 'time'
      fields = %w[timestamp ts at mtime created_at updated_at started_at finished_at completed_at ended_at queued_at scheduled_at last_run next_run last_hit last_io oldest newest]
      results = %w[2026-01-15T12:00:00Z 2026-07-15T12:00:00Z].map do |iso|
        time = Time.iso8601(iso)
        values = [time.to_i, iso, time.getlocal('+05:30').iso8601, time.freeze, time.getlocal('+05:30').to_s]
        nested = { records: values.map { |value| fields.to_h { |field| [field, value] }.freeze }.freeze }.freeze
        before = Marshal.dump(nested)
        text = PWN::Plugins::REPL.pwn_ai_result_text(value: nested)
        raise 'source mutated' unless Marshal.dump(nested) == before
        text.lines.filter_map { |line| line.strip.split(': ', 2).last if line.include?(': ') }
      end
      puts JSON.generate(results)
    RUBY
    {
      'America/Denver' => ['2026-01-15 05:00:00-0700', '2026-07-15 06:00:00-0600'],
      'Asia/Kolkata' => ['2026-01-15 17:30:00+0530', '2026-07-15 17:30:00+0530']
    }.each do |zone, expected|
      stdout, stderr, status = Open3.capture3({ 'TZ' => zone }, RbConfig.ruby, '-Ilib', '-e', script)
      expect(status.success?).to be(true), stderr
      JSON.parse(stdout).zip(expected).each do |stamps, stamp|
        expect(stamps.length).to eq(90)
        expect(stamps.uniq).to eq([stamp])
      end
    end
  end

  it 'renders session mtime oldest first without changing the returned records' do
    records = [{ id: 'new', mtime: '2026-10-09T12:00:00Z' }, { id: 'old', mtime: '2026-10-08T12:00:00Z' }]
    original = Marshal.dump(records)
    text = repl.pwn_ai_result_text(value: records)
    expect(text).to eq("1.\n  id: old\n  mtime: #{local_stamp('2026-10-08T12:00:00Z')}\n2.\n  id: new\n  mtime: #{local_stamp('2026-10-09T12:00:00Z')}")
    expect(Marshal.dump(records)).to eq(original)
  end

  it 'sorts mixed epoch, ISO and Time instants stably across zones before rounding display seconds' do
    records = [
      { id: 'new', timestamp: Time.new(2026, 10, 9, 12, 0, 0, '+00:00') },
      { id: 'equal-first', timestamp: '1970-01-01T01:00:00+01:00' },
      { id: 'fraction-new', timestamp: 0.9 },
      { id: 'equal-second', timestamp: 0 },
      { id: 'fraction-old', timestamp: 0.1 },
      { id: 'old', timestamp: -1 }
    ]
    text = repl.pwn_ai_result_text(value: records)
    expect(text.scan(/id: (.+)/).flatten).to eq(%w[old equal-first equal-second fraction-old fraction-new new])
    expect(text).to include("timestamp: #{local_stamp('1969-12-31T23:59:59Z')}", "timestamp: #{local_stamp('1970-01-01T01:00:00+01:00')}", "timestamp: #{local_stamp('2026-10-09T12:00:00Z')}")
  end

  it 'keeps undated and invalid records stable before dated records with valid fallback fields' do
    records = [
      { id: 'new', timestamp: 10 }, { id: 'missing' }, { id: 'invalid', timestamp: 'yesterday' },
      { id: 'nil-record', timestamp: nil }, { id: 'false-record', timestamp: false },
      { id: 'fallback', timestamp: 'bad', created_at: 0 }, { id: 'infinite', timestamp: Float::INFINITY }
    ]
    text = repl.pwn_ai_result_text(value: records)
    expect(text.scan(/id: (.+)/).flatten).to eq(%w[missing invalid nil-record false-record infinite fallback new])
    expect(text).to include('timestamp: yesterday', 'timestamp: null', 'timestamp: false', 'timestamp: Infinity', 'timestamp: bad')
  end

  it 'orders keyed cron and memory collections recursively without reordering record fields' do
    value = {
      cron: { recent: { id: 'cron-new', created_at: 10, last_run: 0 }, older: { id: 'cron-old', created_at: 0, last_run: 20 } },
      memory: { recent: { value: 'memory-new', timestamp: 10, last_hit: 0 }, older: { value: 'memory-old', timestamp: 0, last_hit: 20 } },
      learning: [{ task: 'new-task', timestamp: 10 }, { task: 'old-task', timestamp: 0 }],
      swarm: { ok: true, messages: [{ content: 'new-message', ts: 10 }, { content: 'old-message', ts: 0 }] }
    }
    original = Marshal.dump(value)
    text = repl.pwn_ai_result_text(value: value)
    [%w[cron-old cron-new], %w[memory-old memory-new], %w[old-task new-task], %w[old-message new-message]].each do |old, newer|
      expect(text.index(old)).to be < text.index(newer)
    end
    expect(text).to include("id: cron-old\n    created_at: #{local_stamp('1970-01-01T00:00:00Z')}\n    last_run: #{local_stamp('1970-01-01T00:00:20Z')}")
    expect(Marshal.dump(value)).to eq(original)
  end

  it 'does not infer timestamps from IDs, durations, prose, scalar arrays or untimed records' do
    value = {
      id: 1_700_000_000, duration: 1_700_000_000, ttl: 120, age_s: 30,
      text: '2026-10-09T12:00:00Z', code: '{"timestamp":0}', timestamp: '1700000000',
      steps: [{ name: 'z' }, { name: 'a' }], args: [3, 1, 2],
      mixed: [{ id: 'new', timestamp: 10 }, 'separator', { id: 'old', timestamp: 0 }]
    }
    text = repl.pwn_ai_result_text(value: value)
    expect(text).to include('id: 1700000000', 'duration: 1700000000', 'ttl: 120', 'age_s: 30',
                            'text: 2026-10-09T12:00:00Z', 'code: {"timestamp":0}', 'timestamp: "1700000000"',
                            "steps:\n  1.\n    name: z\n  2.\n    name: a", "args:\n  1. 3\n  2. 1\n  3. 2")
    expect(text.index('id: new')).to be < text.index('id: old')
  end

  it 'formats all recognized menu timestamp fields and session stats with exact timezone offsets' do
    fields = %w[timestamp ts at mtime created_at updated_at started_at finished_at completed_at ended_at queued_at scheduled_at last_run next_run last_hit last_io oldest newest]
    fields.each do |field|
      expect(repl.pwn_ai_result_text(value: { field => '2026-10-09T12:00:00.123456-06:00' })).to eq("#{field}: #{local_stamp('2026-10-09T12:00:00.123456-06:00')}")
    end
  end

  it 'redacts frozen structured and serialized provider results without changing their source values' do
    value = [{ id: 'new', created_at: 10, client_secret: "first-secret\nsecond-secret" }.freeze,
             { id: 'old', created_at: 0, enabled: false, result: nil }.freeze].freeze
    original = Marshal.dump(value)
    [value, JSON.generate(value)].each do |input|
      text = repl.pwn_ai_result_text(value: input)
      expect(text.index('id: old')).to be < text.index('id: new')
      expect(text).to include("created_at: #{local_stamp('1970-01-01T00:00:00Z')}", 'client_secret: [REDACTED:client_secret:', 'enabled: false', 'result: null')
      expect(text).not_to include('first-secret', 'second-secret')
    end
    expect(Marshal.dump(value)).to eq(original)
  end

  it 'keeps long command output complete at the live bottom without reordering the transcript' do
    value = (0..300).to_a.reverse.map { |epoch| { id: "row-#{epoch}", timestamp: epoch, content: 'complete value ' * 6 } }
    queue = Queue.new
    repl.pwn_ai_print_result(value: value, output: PWN::Plugins::REPL::AIConsole::EventIO.new(queue))
    type, text = queue.pop
    expect(type).to eq(:command)
    expect(text.bytesize).to be > 16_384
    expect(text.scan(/id: row-(\d+)/).flatten.map(&:to_i)).to eq((0..300).to_a)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: Curses, getch: nil)
    console.add(:operator, 'original request')
    console.add(type, text)
    expect(console.instance_variable_get(:@timeline).map { |row| row.take(2) }).to eq([[:operator, 'original request'], [:command, text]])
    expect(console.instance_variable_get(:@scroll)).to be_nil
  end

  it 'does not normalize malformed clock times or timezone offsets into different instants' do
    %w[2026-01-01T24:00:00Z 2026-01-01T00:60:00Z 2026-01-01T00:00:99Z 2026-01-01T00:00:00+00:99 2026-01-01T00:00:00+25:00].each do |value|
      expect(repl.pwn_ai_result_text(value: { timestamp: value })).to eq("timestamp: #{value}")
    end
  end

  it 'preserves invalid calendar dates and formats serialized Ruby Time values' do
    value = { created_at: '2026-02-30T00:00:00Z', updated_at: '2026-10-09 12:00:00 +0530' }
    expect(repl.pwn_ai_result_text(value: value)).to eq("created_at: 2026-02-30T00:00:00Z\nupdated_at: #{local_stamp('2026-10-09T12:00:00+05:30')}")
  end
end

describe 'menu chronology routing' do
  include_context 'pwn tmp sandbox'

  let(:pry) { Pry.new }
  let(:repl) { PWN::Plugins::REPL }
  let(:records) { [{ id: 'new-record', timestamp: 10 }, { id: 'old-record', timestamp: 0 }] }

  {
    '/sessions list' => ['PWN::Sessions', :catalog, :nested],
    '/cron list' => ['PWN::Cron', :list, :map],
    '/cron create hourly fixture' => ['PWN::Cron', :create, :nested],
    '/cron run fixture' => ['PWN::Cron', :run, :json],
    '/memory list' => ['PWN::Memory', :recall, :map],
    '/memory recall fixture' => ['PWN::Memory', :recall, :map],
    '/learning list' => ['PWN::AI::Agent::Learning', :outcomes, :array],
    '/learning list --conflicted' => ['PWN::AI::Agent::Learning', :list_conflicted, :array],
    '/learning requeue' => ['PWN::AI::Agent::Learning', :requeue_conflicted, :nested],
    '/mcp fixture call tool' => ['PWN::AI::MCP', :invoke, :json]
  }.each do |line, (namespace, method, shape)|
    it "presents chronological #{shape} results through #{line}" do
      result = case shape
               when :array then records
               when :map then { recent: records.first, older: records.last }
               when :nested then { results: records }
               when :json then JSON.generate(results: records)
               end
      result = { sessions: [{ id: 'new-record', mtime: 10 }, { id: 'old-record', mtime: 0 }] } if line == '/sessions list'
      original = Marshal.dump(result)
      allow(Object.const_get(namespace)).to receive(method).and_return(result)
      allow(PWN::AI::MCP).to receive(:backends).and_return([{ name: 'fixture' }]) if namespace == 'PWN::AI::MCP'
      output = StringIO.new
      original_stdout = $stdout
      begin
        $stdout = output
        repl.pwn_ai_dispatch_slash!(request: line, pry: pry)
      ensure
        $stdout = original_stdout
      end
      text = output.string
      expect(text.index('id: old-record')).to be < text.index('id: new-record')
      field = line == '/sessions list' ? 'mtime' : 'timestamp'
      expect(text).to include("#{field}: #{Time.at(0).getlocal.strftime('%Y-%m-%d %H:%M:%S%z')}")
      expect(Marshal.dump(result)).to eq(original)
    end
  end

  it 'presents nested swarm tail timestamps through both legacy and curses command paths' do
    controller = instance_double(PWN::Plugins::REPL::AISwarm::Controller)
    result = { ok: true, messages: [{ ts: 10, content: 'new-message' }, { ts: 0, content: 'old-message' }] }
    allow(controller).to receive(:execute).and_return(result)
    pry.config.pwn_ai_swarm = controller
    expect { repl.pwn_ai_dispatch_slash!(request: '/swarm tail', pry: pry) }.to output(/old-message.*new-message/m).to_stdout
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: Curses, getch: nil)
    console.instance_variable_set(:@swarm, controller)
    console.run_swarm('/swarm tail')
    expect(console.instance_variable_get(:@timeline).last.take(2)).to eq([:command, repl.pwn_ai_result_text(value: result)])
  end
end
