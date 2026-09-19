# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Jobs do
  before do
    @root = Dir.mktmpdir('pwn-jobs-')
    stub_const('PWN::Plugins::Jobs::JOBS_DIR', @root)
  end

  after do
    FileUtils.remove_entry(@root)
  end

  def fresh(code)
    setup = "require 'pwn'; PWN::Plugins::Jobs.send(:remove_const, :JOBS_DIR); PWN::Plugins::Jobs.const_set(:JOBS_DIR, #{described_class::JOBS_DIR.inspect}); "
    out, err, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../../../../lib', __dir__), '-e', setup + code)
    raise err unless status.success?

    JSON.parse(out, symbolize_names: true)
  end

  def finished(id)
    Timeout.timeout(8) do
      loop do
        row = described_class.status(id: id)
        return row unless row[:status] == 'RUNNING'

        sleep 0.05
      end
    end
  end

  it 'survives an exited creator and records completion in a fresh session' do
    row = fresh("puts JSON.generate(PWN::Plugins::Jobs.start(command: 'sleep 2; printf durable', max_runtime: 21600, session_id: 'old'))")
    expect(row[:status]).to eq('RUNNING')
    expect(row[:worker_pid]).to be_a(Integer)
    expect(row[:worker_identity]).not_to be_nil
    worker_session = Process.getsid(row[:worker_pid])
    expect(fresh("puts JSON.generate(PWN::Plugins::Jobs.status(id: '#{row[:id]}'))")[:status]).to eq('RUNNING')
    done = finished(row[:id])
    expect(worker_session).to eq(row[:worker_pid])
    expect(done).to include(status: 'COMPLETED', exit_code: 0, max_runtime: 21_600, session_id: 'old')
    expect(done[:finished_at]).not_to be_nil
    expect(fresh("puts JSON.generate(PWN::Plugins::Jobs.result(id: '#{row[:id]}'))")[:tail]).to eq('durable')
  end

  it 'enforces timeout without polling and kills a TERM-resistant process tree' do
    marker = File.join(@root, 'escaped')
    row = described_class.start(command: "trap '' TERM; (sleep 2; touch #{marker}) & wait", max_runtime: 0.2)
    sleep 2.5
    persisted = JSON.parse(File.read(File.join(@root, "#{row[:id]}.json")), symbolize_names: true)
    expect(persisted).to include(status: 'TIMEOUT', signal: 9)
    expect(File.exist?(marker)).to be(false)
  end

  it 'cancels durably without directly signaling a persisted PID' do
    row = described_class.start(command: "trap '' TERM; sleep 10", max_runtime: 10)
    expect(described_class.stop(handle: row[:id])).to be(true)
    expect(File.exist?(File.join(@root, "#{row[:id]}.cancel"))).to be(true)
    expect(finished(row[:id])).to include(status: 'STOPPED', signal: 9)
    expect(described_class.stop(id: row[:id])).to be(false)
  end

  it 'pages binary logs with byte offsets and distinguishes EOF from completion' do
    row = described_class.start(command: "printf 'abc\\377def'; sleep 1", max_runtime: 5)
    first = Timeout.timeout(8) do
      loop do
        page = described_class.job_tail(handle: row[:id], offset: 0, length: 4)
        break page if page[:bytes].to_i.positive?

        raise 'job ended before log bytes' unless page[:status] == 'RUNNING'

        sleep 0.05
      end
    end
    expect(first).to include(bytes: 4, next_offset: 4, encoding: 'base64', eof: false, status: 'RUNNING')
    expect(Base64.strict_decode64(first[:data])).to eq("abc\xFF".b)
    last = described_class.tail(id: row[:id], offset: 4, length: 100)
    expect(last).to include(body: 'def', data: 'def', bytes: 3, next_offset: 7, eof: true, status: 'RUNNING')
    finished(row[:id])
    expect(described_class.tail(id: row[:id], offset: 7)).to include(bytes: 0, eof: true, status: 'COMPLETED')
    expect(described_class.tail(id: row[:id])).to be_a(String)
  end

  it 'filters and limits durable jobs across sessions' do
    first = described_class.start(command: 'true', session_id: 'one')
    finished(first[:id])
    second = described_class.start(command: 'true', session_id: 'two')
    finished(second[:id])
    expect(described_class.list(session_id: 'one', limit: 1).map { |row| row[:id] }).to eq([first[:id]])
    expect(described_class.list(limit: 1).size).to eq(1)
  end

  it 'records real nonzero exits, signals and spawn errors' do
    row = described_class.start(command: 'exit 7')
    expect(finished(row[:id])).to include(status: 'FAILED', exit_code: 7, signal: nil)
    row = described_class.start(command: 'kill -TERM $$')
    expect(finished(row[:id])).to include(status: 'FAILED', exit_code: nil, signal: 15)
    row = described_class.start(command: 'true', cwd: File.join(@root, 'absent'))
    expect(finished(row[:id])).to include(status: 'FAILED')
    expect(finished(row[:id])[:error]).to include('ENOENT')
  end

  it 'reuses an idempotency key across concurrent fresh creators' do
    command = "printf once >> #{@root}/runs"
    code = "puts JSON.generate(PWN::Plugins::Jobs.start(command: #{command.inspect}, idempotency_key: 'retry'))"
    rows = 2.times.map { Thread.new { fresh(code) } }.map(&:value)
    expect(rows.map { |row| row[:id] }.uniq.size).to eq(1)
    finished(rows.first[:id])
    expect(File.read(File.join(@root, 'runs'))).to eq('once')
  end

  it 'marks a dead supervisor LOST and never signals a reused metadata PID' do
    row = described_class.start(command: 'sleep 1', max_runtime: 5)
    Process.kill('KILL', row[:worker_pid])
    sleep 0.1
    path = File.join(@root, "#{row[:id]}.json")
    meta = JSON.parse(File.read(path))
    meta['pid'] = Process.pid
    File.write(path, JSON.generate(meta))
    expect(described_class.status(id: row[:id])).to include(status: 'LOST')
    expect(described_class.stop(id: row[:id])).to be(false)
    expect(JSON.parse(File.read(path))['status']).to eq('LOST')
    sleep 1
  end

  it 'honors cwd and string environment maps with private files and nil defaults' do
    row = described_class.start(cmd: 'printf "$JOB_TEST:$PWD"', cwd: @root, env: { 'JOB_TEST' => 'value' }, max_runtime: nil, session_id: nil, idempotency_key: nil)
    expect(finished(row[:id])).to include(max_runtime: 0)
    expect(described_class.result(id: row[:id])[:tail]).to eq("value:#{@root}")
    expect(File.stat(@root).mode & 0o777).to eq(0o700)
    expect(File.stat(row[:log]).mode & 0o777).to eq(0o600)
    expect(File.stat(File.join(@root, "#{row[:id]}.json")).mode & 0o777).to eq(0o600)
    expect { described_class.status(handle: '../invalid') }.to raise_error(ArgumentError)
    expect { described_class.start(command: 'true', env: { nope: 1 }) }.to raise_error(ArgumentError)
  end

  it 'preserves synchronous graph dependencies and drains skipped descendants' do
    graph = described_class.graph(artifact_dir: @root, jobs: [
                                    { id: 'a', command: 'exit 1' },
                                    { id: 'b', command: 'true', needs: ['a'] },
                                    { id: 'c', command: 'true', needs: ['b'] }
                                  ])
    expect(graph[:ok]).to be(false)
    expect(graph[:jobs]['c'][:skipped]).to be(true)
  end

  it 'treats pre-supervisor metadata as unknown rather than inventing completion' do
    id = '0123456789ab'
    File.write(File.join(@root, "#{id}.json"), JSON.generate(id: id, pid: Process.pid, started_at: Time.now.utc.iso8601))
    expect(described_class.status(id: id)).to include(status: 'LOST', alive: false)
    expect(described_class.stop(id: id)).to be(false)
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end
end
