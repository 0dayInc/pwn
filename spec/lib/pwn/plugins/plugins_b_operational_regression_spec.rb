# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::DAOLDAP do
  it '[B001] uses the documented default LDAP port' do
    client = instance_double(Net::LDAP, bind: true)
    expect(Net::LDAP).to receive(:new).with(hash_including(port: 636)).and_return(client)
    expect(described_class.connect(host: 'ldap.example.test', username: 'fixture', password: 'fixture')).to eq(client)
  end
end

RSpec.describe PWN::Plugins::Vsphere do
  it '[B002] closes the authenticated connection on logout' do
    client = double('vsphere connection')
    expect(client).to receive(:close)
    described_class.logout(vsphere_obj: client)
  end
end

RSpec.describe PWN::Plugins::IPInfo do
  it '[B003] returns no addresses on a resolver failure' do
    resolver = instance_double(Resolv::DNS)
    allow(Resolv::DNS).to receive(:new).and_return(resolver)
    allow(resolver).to receive(:getaddresses).and_raise(Resolv::ResolvError)
    allow(resolver).to receive(:close)
    expect(PWN::Plugins::Sock).not_to receive(:check_port_in_use)
    expect(described_class.get(target: 'missing.example.test', skip_api: true)).to eq([])
  end
end

RSpec.describe PWN::Plugins::IPInfo do
  it '[B004] keeps each resolved address and its TLS result independent' do
    resolver = instance_double(Resolv::DNS, getaddresses: %w[10.0.0.1 203.0.113.2])
    allow(Resolv::DNS).to receive(:new).and_return(resolver)
    allow(resolver).to receive(:close)
    allow(PWN::Plugins::Sock).to receive(:check_port_in_use).with(server_ip: '10.0.0.1', port: 443).and_return(false)
    allow(PWN::Plugins::Sock).to receive(:check_port_in_use).with(server_ip: '203.0.113.2', port: 443).and_return(true)
    allow(PWN::Plugins::Sock).to receive(:get_tls_cert).and_return(nil)
    rows = described_class.get(target: 'fixture.example.test', skip_api: true)
    expect(rows.map { |row| row.slice(:ip, :is_rfc1918, :tls_avail) }).to eq([
                                                                               { ip: '10.0.0.1', is_rfc1918: true, tls_avail: false },
                                                                               { ip: '203.0.113.2', is_rfc1918: false, tls_avail: true }
                                                                             ])
  end
end

RSpec.describe PWN::Plugins::IPInfo do
  it '[B005] preserves a validation failure before a results file is opened' do
    expect { described_class.bruteforce_subdomains(parent_domain: '') }.to raise_error(RuntimeError, /parent_domain parameter is required/)
  end
end

RSpec.describe PWN::Plugins::Debugger do
  it '[B006] consumes complete MI records through ProcessTube' do
    reader, writer = IO.pipe
    commands = StringIO.new
    tube = PWN::Plugins::ProcessTube.register(io: reader, w: commands)
    allow(PWN::Plugins::ProcessTube).to receive(:dump_scrollback)
    described_class.send(:store_session, handle: tube[:id], tube: tube)
    writer.write("^done,register-values=[{number=\"16\",value=\"0x4141\"}]\n^done,memory=[{begin=\"0x1000\",contents=\"4142\"}]\n")
    expect(described_class.regs(handle: tube[:id])[:registers]).to eq('16' => '0x4141')
    expect(described_class.read_mem(handle: tube[:id], addr: '0x1000', len: 2)[:memory]).to eq(addr: '0x1000', hex: '4142')
  ensure
    described_class.close(handle: tube[:id]) if tube
    writer&.close
  end
end

RSpec.describe PWN::Plugins::GDB do
  it '[B007] forwards debug_session script commands before running the inferior' do
    allow(PWN::Plugins::PreflightChecker).to receive(:require_bin!)
    status = instance_double(Process::Status, exitstatus: 0)
    expect(Open3).to receive(:capture3).with('gdb', '--batch', '--quiet', '-ex', 'set pagination off', '-ex', 'break main', '-ex', 'run', '-ex', 'bt', '-ex', 'info registers', '--args', '/fixture').and_return(['', '', status])
    described_class.debug_session(binary: '/fixture', script: ['break main'])
  end
end

RSpec.describe PWN::Plugins::AFLplusplus do
  it '[B008] passes the campaign runtime budget to AFL++' do
    Dir.mktmpdir('pwn-afl-budget-') do |dir|
      received = nil
      allow(described_class).to receive(:system) { |*argv, **_kw|
        received = argv
        true
      }
      described_class.campaign(in_dir: File.join(dir, 'in'), out_dir: File.join(dir, 'out'), target: 'fixture-target @@', max_runtime: 7, handoff: false)
      expect(received.drop(1)).to include('-V', '7')
    end
  end
end

RSpec.describe PWN::Plugins::Char do
  it '[B009] preserves UTF-8 bytes and never retags caller strings in place' do
    text = 'café'
    expect(described_class.force_utf8(obj: text)).to eq(text)
    bytes = text.b.freeze
    expect(described_class.force_utf8(obj: [bytes])).to eq([text])
    expect(bytes.encoding).to eq(Encoding::BINARY)
    expect(described_class.force_utf8(obj: "caf\xE9".b)).to eq(text)
  end
end

RSpec.describe PWN::Plugins::PreflightChecker do
  it '[B010] rejects executable directories as missing binaries' do
    Dir.mktmpdir('pwn-path-') do |dir|
      FileUtils.mkdir_p(File.join(dir, 'fake-bin'))
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('PATH').and_return(dir)
      expect(described_class.bin?(name: 'fake-bin')).to be(false)
      expect { described_class.require_bin!(name: 'fake-bin') }.to raise_error(described_class::MissingBinary)
    end
  end
end

RSpec.describe 'bodyless REST success responses' do
  before do
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(RestClient::Request).to receive(:execute).and_return(instance_double(RestClient::Response, body: '', code: 204))
  end

  it '[B011] returns an empty result for GitHub 204 responses' do
    expect(PWN::Plugins::Github.api(method: :delete, path: 'fixture', token: 'fixture')).to eq({})
  end

  it '[B011] returns an empty result after deleting a HackerOne intent' do
    expect(PWN::Plugins::HackerOne.delete_report_intent(id: 'fixture', username: 'fixture', api_key: 'fixture')).to eq({})
  end
end

RSpec.describe PWN::Plugins::NexposeVulnScan do
  it '[B012] reaches the stale-asset query after matching the requested site' do
    site = double('site', id: 7, name: 'lab')
    client = double('nexpose', list_sites: [site], filter: [])
    expect(described_class.delete_site_assets_older_than(nsc_obj: client, site_name: 'lab', days: 30)).to eq(client)
  end
end

RSpec.describe PWN::Plugins::NexposeVulnScan do
  it '[B013] refuses to report a scan as completed when the site is absent' do
    client = double('nexpose', list_sites: [], scan_activity: [])
    expect(client).not_to receive(:scan_site)
    expect { described_class.scan_site_by_name(nsc_obj: client, site_name: 'absent') }.to raise_error(/does not exist/)
  end
end

RSpec.describe PWN::Plugins::Fuzz do
  it '[B014] sends a plain request template as actual wire bytes' do
    socket = double('socket', wait_readable: false)
    allow(PWN::Plugins::Sock).to receive(:connect).and_return(socket)
    allow(PWN::Plugins::Sock).to receive(:disconnect).with(sock_obj: socket).and_return(nil)
    expect(socket).to receive(:write).with("GET /café HTTP/1.0\r\n\r\n".b)
    rows = described_class.socket(target: 'fixture', port: 1, request: "GET /♥seed♥ HTTP/1.0\r\n\r\n", payload: 'café', request_rate_limit: 0)
    expect(rows.first[:response]).to eq('')
  end
end

RSpec.describe PWN::Plugins::Fuzz do
  it '[B015] bounds response reads when a peer keeps its connection open' do
    socket, peer = UNIXSocket.pair
    allow(PWN::Plugins::Sock).to receive(:connect).and_return(socket)
    allow(PWN::Plugins::Sock).to receive(:disconnect) { |opts|
      opts[:sock_obj].close unless opts[:sock_obj].closed?
      nil
    }
    peer.write('ok')
    rows = Timeout.timeout(0.5) do
      described_class.socket(target: 'fixture', port: 1, request: '♥x♥', payload: 'A', response_timeout: 0.05, request_rate_limit: 0)
    end
    expect(rows.first).to include(response: '"ok"', response_len: 2)
  ensure
    socket&.close unless socket&.closed?
    peer&.close unless peer&.closed?
  end
end

RSpec.describe PWN::Plugins::GoogleWorkspace do
  it '[B016] escapes apostrophes and backslashes in literal Drive searches' do
    query = "O'Reilly\\guide"
    expect(described_class).to receive(:api).with(hash_including(params: hash_including(q: "fullText contains 'O\\'Reilly\\\\guide'"))).and_return(files: [])
    expect(described_class.drive_search(query: query)).to eq([])
  end
end

RSpec.describe PWN::Plugins::Findings do
  it '[B017] never closes a finding when the reproduction command failed' do
    Dir.mktmpdir('pwn-retest-') do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      allow(Dir).to receive(:home).and_return(dir)
      row = { id: 'fixture', title: 'fixture', status: 'open', severity: 'high', claimed_severity: 'high', verification_status: 'reproduced', reproduction_steps: ['exit 7'] }
      File.write(described_class::FILE, "#{JSON.generate(row)}\n")
      expect { described_class.retest(id: 'fixture', kind: 'script', impact: 'FIXTURE_IMPACT') }.to raise_error(IOError, /reproduction failed/)
      expect(described_class.report.first).to eq(row)
    end
  end
end

RSpec.describe PWN::Plugins::GoogleWorkspace do
  it '[B018] removes the persisted refresh token on revocation' do
    Dir.mktmpdir('pwn-revoke-') do |dir|
      path = File.join(dir, 'fixture.yaml')
      File.write(path, 'fixture')
      stub_const('PWN::Plugins::GoogleWorkspace::PENDING_FILE', File.join(dir, 'pending'))
      oauth = { bearer_token: 'fixture-bearer', refresh_token: 'fixture-refresh', expires_at: 123 }
      vault = { plugins: { google_workspace: { oauth: oauth.dup } } }
      stub_const('PWN::Env', { plugins: { google_workspace: { oauth: oauth.dup } }, driver_opts: { pwn_env_path: path } })
      allow(RestClient).to receive(:post).and_return('')
      allow(PWN::Plugins::Vault).to receive(:update).and_yield(vault)
      described_class.revoke
      expect(vault.dig(:plugins, :google_workspace, :oauth)).to include(bearer_token: '', refresh_token: nil, expires_at: nil)
    end
  end
end

RSpec.describe PWN::Plugins::DefectDojo do
  it '[B019] supports engagement lookup by id without pagination fields' do
    allow(described_class).to receive(:rest_call).with(dd_obj: {}, rest_call: 'engagements/7', params: { o: 'name', limit: 25 }).and_return('{"id":7,"name":"fixture"}')
    expect(described_class.engagement_list(dd_obj: {}, id: 7)).to eq(id: 7, name: 'fixture')
  end
end

RSpec.describe PWN::Plugins::DefectDojo do
  it '[B020] creates the requested engagement type with optional tools omitted' do
    allow(described_class).to receive(:user_list).and_return(results: [{ username: 'lead', id: 1 }])
    allow(described_class).to receive(:product_list).and_return(results: [{ name: 'product', id: 2 }])
    allow(described_class).to receive(:tool_configuration_list).and_return(results: [])
    expect(described_class).to receive(:rest_call).with(hash_including(http_body: hash_including(engagement_type: 'Interactive', orchestration_engine: nil))).and_return('created')
    expect(described_class.engagement_create(dd_obj: { api_version: 'v2' }, name: 'fixture', lead_username: 'lead', product_name: 'product', engagement_type: 'Interactive')).to eq('created')
  end
end

RSpec.describe 'REST error propagation' do
  before do
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(RestClient::Request).to receive(:execute).and_raise(RestClient::Unauthorized)
  end

  it '[B021] preserves the DefectDojo HTTP exception' do
    expect { PWN::Plugins::DefectDojo.product_list(dd_obj: { url: 'https://fixture.test', api_version: 'v2' }) }.to raise_error(RestClient::Unauthorized)
  end

  it '[B021] preserves the VIN HTTP exception' do
    expect { PWN::Plugins::VIN.get_all_makes }.to raise_error(RestClient::Unauthorized)
  end
end

RSpec.describe PWN::Plugins::TransparentBrowser do
  it '[B022] stops retrying when both JavaScript forms fail' do
    calls = 0
    browser = double('browser')
    allow(browser).to receive(:execute_script) do
      calls += 1
      raise 'unbounded retry' if calls > 2

      raise Selenium::WebDriver::Error::JavascriptError, 'invalid JavaScript'
    end
    expect { described_class.console(browser_obj: { type: :chrome, browser: browser }, js: 'broken()') }.to raise_error(Selenium::WebDriver::Error::JavascriptError)
    expect(calls).to eq(2)
  end
end

RSpec.describe PWN::Plugins::TransparentBrowser do
  it '[B023] does not close the last tab for a nonmatching selector' do
    tabs = [{ index: 'actual', title: 'Keep', url: 'https://fixture.test', state: :active }]
    allow(described_class).to receive(:list_tabs).and_return(tabs)
    allow(described_class).to receive(:close)
    browser = { type: :chrome, browser: Object.new }
    expect(described_class.close_tab(browser_obj: browser, index: 'missing')).to eq(tabs)
    expect(described_class.close_tab(browser_obj: browser, keyword: 'not-present')).to eq(tabs)
    expect(described_class).not_to have_received(:close)
  end
end

RSpec.describe PWN::Plugins::BinaryParser do
  it '[B024] resolves a static ELF with load segments but no dynamic table' do
    Dir.mktmpdir('pwn-static-elf-') do |dir|
      path = File.join(dir, 'fixture')
      ident = "\x7fELF\x02\x01\x01".b.ljust(16, "\0")
      header = [2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0].pack('vvVQ<Q<Q<Vvvvvvv')
      load = [1, 5, 0, 0x400000, 0x400000, 120, 120, 4096].pack('VVQ<Q<Q<Q<Q<Q<')
      File.binwrite(path, ident + header + load)
      expect(described_class.elf_resolve(path: path)).to include(arch: 'x86_64', got: {}, plt: {}, symbols: {})
    end
  end
end

RSpec.describe PWN::Plugins::Jobs do
  it '[B025] terminates a timed-out graph command before its later write' do
    Dir.mktmpdir('pwn-graph-deadline-') do |dir|
      graph = described_class.graph(artifact_dir: dir, jobs: [{ id: 'slow', command: 'sleep 0.4; printf late > marker; sleep 0.5', timeout: 0.05 }])
      expect(graph[:jobs]['slow']).to include(timeout: true, exit: 124)
      expect(File.exist?(File.join(dir, 'marker'))).to be(false)
    end
  end
end

RSpec.describe PWN::Plugins::DAOLDAP do
  it '[B026] rejects an unsuccessful LDAP bind rather than returning an authenticated handle' do
    client = instance_double(Net::LDAP, bind: false)
    allow(Net::LDAP).to receive(:new).and_return(client)
    expect { described_class.connect(host: 'ldap.example.test', username: 'fixture', password: 'fixture') }.to raise_error(IOError, /LDAP bind failed/)
  end
end

RSpec.describe PWN::Plugins::DAOMongo do
  it '[B027] loads its driver when the plugin is loaded in a fresh Ruby process' do
    code = "require 'pwn/plugins/dao_mongo'; abort 'Mongo::Client not loaded' unless defined?(Mongo::Client)"
    out, status = Open3.capture2e(RbConfig.ruby, '-I', File.expand_path('../../../../lib', __dir__), '-e', code)
    expect(status.success?).to be(true), out
  end
end

RSpec.describe PWN::Plugins::NexposeVulnScan do
  it '[B028] accepts the documented Array of recurring report names' do
    report = double('report', name: 'weekly', status: 'Generated', uri: '/reports/weekly.pdf')
    client = double('nexpose')
    polls = 0
    allow(client).to receive(:reports) do
      polls += 1
      raise 'report loop did not finish' if polls > 1

      [report]
    end
    expect(client).to receive(:download).with('/reports/weekly.pdf', 'weekly.pdf')
    expect(described_class.download_recurring_report(nsc_obj: client, report_names: ['weekly'], poll_interval: 0)).to eq(client)
  end
end

RSpec.describe PWN::Plugins::GoogleWorkspace do
  it '[B029] replies using RFC Message-ID and Reply-To rather than the API id' do
    message = { id: 'api-id', threadId: 'thread-id', payload: { headers: [
      { name: 'From', value: 'sender@example.test' }, { name: 'Reply-To', value: 'reply@example.test' },
      { name: 'Subject', value: 'Fixture' }, { name: 'Message-ID', value: '<message@example.test>' }
    ] } }
    allow(described_class).to receive(:api).with(hash_including(url: "#{described_class::GMAIL_API}/users/me/messages/api-id")).and_return(message)
    expect(described_class).to receive(:api).with(hash_including(http_method: :post)) do |options|
      raw = Base64.urlsafe_decode64(options[:http_body][:raw])
      expect(raw).to include('To: reply@example.test', 'In-Reply-To: <message@example.test>', 'References: <message@example.test>')
      expect(options[:http_body][:threadId]).to eq('thread-id')
      { id: 'sent', threadId: 'thread-id' }
    end
    described_class.gmail_reply(id: 'api-id', body: 'Fixture reply')
  end
end

RSpec.describe PWN::Plugins::Git do
  it '[B030] treats git URLs as a single literal argument rather than shell commands' do
    Dir.mktmpdir('pwn-git-argv-') do |dir|
      fake = File.join(dir, 'git')
      File.write(fake, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
      File.chmod(0o700, fake)
      old_path = ENV.fetch('PATH', '')
      ENV['PATH'] = "#{dir}:#{old_path}"
      marker = File.join(dir, 'marker')
      url = "repo name; printf bad > #{marker}"
      response = described_class.dump_all_repo_branches(git_url: url)
      expect(File.exist?(marker)).to be(false)
      expect(response.lines.map(&:chomp)).to eq(['ls-remote', '--', url])
    ensure
      ENV['PATH'] = old_path
    end
  end
end

RSpec.describe PWN::Plugins::OpenVAS do
  it '[B031] passes credentials literally and matches quoted task names' do
    expect(described_class).not_to receive(:`)
    expect(Open3).to receive(:capture3).with('sudo', 'runuser', '-u', '_gvm', '--', '/usr/bin/gvm-cli', '--gmp-username', 'fixture', '--gmp-password', "fixture'pass", 'socket', '--xml', anything).and_return(["<get_tasks_response><task id='7'><name>Bob's task</name></task></get_tasks_response>", '', instance_double(Process::Status, success?: true)])
    tasks = described_class.get_task_id(task_name: "Bob's task", username: 'fixture', password: "fixture'pass")
    expect(tasks.xpath('@id').text).to eq('7')
  end
end

RSpec.describe PWN::Plugins::OpenVAS do
  it '[B031] uses argv transport for starting tasks and exporting reports' do
    tasks = Nokogiri::XML("<root><task id='7'/></root>").xpath('/root/task')
    allow(described_class).to receive(:get_task_id).and_return(tasks)
    expect(described_class).not_to receive(:`)
    allow(Open3).to receive(:capture3) do |*argv|
      xml = Nokogiri::XML(argv.last)
      response = case xml.root.name
                 when 'start_task' then '<start_task_response/>'
                 when 'get_report_formats' then "<get_report_formats_response><report_format id='csv'><name>CSV Results</name></report_format></get_report_formats_response>"
                 else
                   "<get_reports_response><report id='8'><task id='7'/>#{Base64.strict_encode64("fixture\n")}</report></get_reports_response>"
                 end
      [response, '', instance_double(Process::Status, success?: true)]
    end
    described_class.start_task(task_name: 'fixture', username: 'fixture', password: 'fixture')
    expect(described_class.last_report_id(task_name: 'fixture', username: 'fixture', password: 'fixture')).to eq('8')
    Dir.mktmpdir('pwn-gvm-report-') do |dir|
      described_class.save_report(report_dir: dir, report_type: 'csv', report_id: '8', username: 'fixture', password: 'fixture')
      expect(File.binread(File.join(dir, 'openvas_results.csv'))).to eq("fixture\n")
    end
  end
end

RSpec.describe PWN::Plugins::BinaryAnalysis do
  it '[B032] never interprets a one-element argv as a shell command' do
    expect { described_class.run(argv: ['printf not-an-executable'], timeout: 1) }.to raise_error(Errno::ENOENT)
  end
end

RSpec.describe PWN::Plugins::DetectOS do
  it '[B033] excludes already wrapped tools from native living-off-the-land inventory' do
    row = described_class.living_off_the_land(distro: 'fixture', version: '1', type: :linux, arch: 'fixture', endian: :little, cap_net_raw: false, docker: false, pwn_bins: ['wrapped'], which: { 'wrapped' => true, 'extra' => true })
    expect(row[:native]).to eq(['extra'])
  end
end

RSpec.describe PWN::Plugins::ExploitDB do
  it '[B034] leaves the destination absent during a sync dry run' do
    Dir.mktmpdir('pwn-sync-dry-') do |dir|
      destination = File.join(dir, 'not-created')
      expect(described_class.sync(dir: destination, dry_run: true)[:dry_run]).to be(true)
      expect(File.exist?(destination)).to be(false)
    end
  end
end

RSpec.describe 'scanner JSONL validation' do
  it '[B035] skips non-object httpx JSON values' do
    row = PWN::Plugins::Httpx.probe(jsonl: "1\ntrue\n[]\n{\"tech\":[\"fixture\"]}\n")
    expect(row[:hosts]).to eq([{ 'tech' => ['fixture'] }])
    expect(row[:techs]).to eq(['fixture'])
  end

  it '[B035] skips non-object nuclei JSON values' do
    row = PWN::Plugins::Nuclei.scan(jsonl: "1\ntrue\n[]\n{\"template-id\":\"fixture\"}\n", record: false)
    expect(row[:findings].map { |finding| finding[:template_id] }).to eq(['fixture'])
  end
end

RSpec.describe PWN::Plugins::OCR do
  it '[B036] rejects a missing image before invoking Tesseract' do
    Dir.mktmpdir('pwn-ocr-missing-') do |dir|
      expect(RTesseract).not_to receive(:new)
      expect { described_class.process(file: File.join(dir, 'absent.png')) }.to raise_error(ArgumentError, /image file/)
    end
  end
end

RSpec.describe PWN::Plugins::SBOM do
  it '[B037] preserves explicit untagged image selection for Trivy' do
    status = instance_double(Process::Status, success?: true)
    expect(Open3).to receive(:capture2).with('trivy', 'image', '--format', 'json', 'fixture-image').and_return(['{"Results":[]}', status])
    expect(described_class.scan(image: 'fixture-image', engine: 'trivy')[:vulns]).to eq([])
  end
end

RSpec.describe 'authenticated REST TLS defaults' do
  before do
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(PWN::Plugins::DefectDojo).to receive(:sleep)
  end

  it '[B038] verifies HTTPS peers on credential-bearing APIs', :aggregate_failures do
    expect(RestClient::Request).to receive(:execute).exactly(4).times do |options|
      expect(options[:verify_ssl]).not_to be(false)
      RestClient::Response.create('{}', Net::HTTPOK.new('1.1', '200', 'OK'), instance_double(RestClient::Request, redirection_history: []))
    end
    PWN::Plugins::Github.api(path: 'fixture', token: 'fixture')
    PWN::Plugins::HackerOne.get_balance(username: 'fixture', api_key: 'fixture')
    PWN::Plugins::DefectDojo.product_list(dd_obj: { url: 'https://fixture.test', api_version: 'v2' })
    PWN::Plugins::VIN.get_all_makes
  end
end

RSpec.describe PWN::Plugins::HackerOne do
  it '[B039] stops after three retries when rate limiting persists' do
    calls = 0
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(described_class).to receive(:sleep)
    allow(RestClient::Request).to receive(:execute) do
      calls += 1
      raise 'unbounded retry' if calls > 4

      raise RestClient::TooManyRequests
    end
    expect { described_class.get_balance(username: 'fixture', api_key: 'fixture') }.to raise_error(RestClient::TooManyRequests)
    expect(calls).to eq(4)
  end
end

RSpec.describe PWN::Plugins::AISandbox do
  it '[B040] refuses strict execution when the isolation profile is not implemented' do
    Dir.mktmpdir('pwn-strict-profile-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      target = File.join(dir, 'outside-artifacts')
      result = described_class.exec(kind: :ruby, mode: :strict, payload: "File.write(#{target.inspect}, 'escaped')")
      expect(result).to include(ok: false)
      expect(result[:error]).to include('strict sandbox profile')
      expect(File.exist?(target)).to be(false)
    end
  end
end

RSpec.describe PWN::Plugins::Detonate do
  it '[B041] refuses synthetic detonation instead of reporting an unexecuted sample as isolated' do
    Dir.mktmpdir('pwn-detonate-unsupported-') do |dir|
      sample = File.join(dir, 'sample')
      File.write(sample, 'fixture')
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'podman').and_return(true)
      expect(Open3).not_to receive(:capture3)
      row = described_class.detonate(path: sample)
      expect(row).to include(isolated: false, executed: false)
      expect(row[:error]).to include('not implemented')
    end
  end
end

RSpec.describe PWN::Plugins::Char do
  it '[B042] keeps each non-character representation in its own output file' do
    Dir.mktmpdir('pwn-char-files-') do |dir|
      allow(described_class).to receive(:generate_by_range).and_return([{ bin: { char: '01000001', encoder: nil }, hex: { char: '41', encoder: nil } }])
      described_class.generate_encoded_files(from: 65, to: 65, output_dir: dir)
      expect(Dir.children(dir).sort).to eq(%w[65_65_bin.txt 65_65_hex.txt])
      expect(File.read(File.join(dir, '65_65_bin.txt'))).to eq("01000001\n")
      expect(File.read(File.join(dir, '65_65_hex.txt'))).to eq("41\n")
    end
  end
end

RSpec.describe PWN::Plugins::MethodCatalog do
  it '[B043] accepts options forwarded to an internal helper without accepting unknown keys' do
    %i[info sections symbols imports exports relocations].each do |method|
      expect(described_class.guard_eval(code: "PWN::Plugins::BinaryParser.#{method}(path: '/fixture')")).to be_nil
      rejected = described_class.guard_eval(code: "PWN::Plugins::BinaryParser.#{method}(not_a_key: '/fixture')")
      expect(rejected[:error]).to include('not_a_key')
    end
  end
end

RSpec.describe PWN::Plugins::Git do
  it '[B044] keeps dates in one argument and escapes the HTML summary' do
    allow(described_class).to receive(:`).and_return('raw <message>')
    expect(Open3).to receive(:capture2).with('git', 'log', '--since', 'last week', '--stat-width=65535', '--graph', err: File::NULL).and_return(['raw <message>', instance_double(Process::Status, success?: true)])
    html = described_class.gen_html_diff(repo: '<repo>', branch: 'main', since: 'last week')
    expect(html).to include('&lt;repo&gt;', 'raw &lt;message&gt;')
    expect(html).not_to include('<repo>', '<message>')
  end

  it '[B045] supports frozen filenames and repository paths containing spaces' do
    Dir.mktmpdir('pwn-author space-') do |dir|
      File.write(File.join(dir, 'file name.rb'), "first\nlast")
      filename = 'file name.rb.JS-BEAUTIFIED'
      allow(described_class).to receive(:`).and_return('')
      expect(Open3).to receive(:capture2).with('git', "--git-dir=#{dir}/.git", 'log', '-L', '1,2:file name.rb', err: File::NULL).and_return(["commit fixture\nAuthor: Fixture\n", instance_double(Process::Status, success?: true)])
      expect(described_class.get_author(repo_root: dir, target_file: filename, entry_beautified: true)).to eq("Author: Fixture\n")
      expect(filename).to eq('file name.rb.JS-BEAUTIFIED')
    end
  end
end

RSpec.describe PWN::Plugins::Char do
  it '[B046] rejects a missing output directory before attempting generation or writing' do
    Dir.mktmpdir('pwn-char-output-') do |dir|
      expect(described_class).not_to receive(:generate_by_range)
      expect { described_class.generate_encoded_files(from: 65, to: 65, output_dir: File.join(dir, 'missing')) }.to raise_error(ArgumentError, /output_dir/)
    end
  end
end

RSpec.describe PWN::Plugins::TransparentBrowser do
  it '[B047] preserves parse failure diagnostics instead of referencing an undefined variable' do
    browser = double('browser', driver: double('driver', on_log_event: nil))
    devtools = double('devtools')
    allow(devtools).to receive(:send_cmd).and_return('result' => { 'result' => { 'value' => 'not-json' } })
    allow(described_class).to receive(:verify_devtools_browser).and_return(true)
    expect { described_class.get_page_state(browser_obj: { browser: browser, devtools: devtools }) }.to raise_error(RuntimeError, /Failed to parse state JSON/)
  end
end

RSpec.describe PWN::Plugins::SSN do
  it '[B048] excludes reserved area numbers from randomized fixture identifiers' do
    [666, :max].each do |boundary|
      allow(Random).to receive(:rand) { |range|
        if range.end > 100
          boundary == :max ? range.end : boundary
        else
          1
        end
      }
      area = described_class.generate(count: 1).first.split('-').first.to_i
      expect(area).to be_between(1, 899)
      expect(area).not_to eq(666)
    end
  end
end

RSpec.describe PWN::Plugins::CreditCard do
  it '[B049] generates every advertised brand using the installed dependency' do
    described_class.list_types.each do |type|
      row = described_class.generate(type: type, count: 1).first
      expect(CreditCardValidations::Detector.new(row[:number]).valid?(type)).to be(true)
      expect(row[:type]).not_to be_nil
    end
  end
end
