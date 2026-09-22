# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports do
  it 'ranks an evidenced critical directed path above isolated high findings without rewriting member CVSS' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'combined.txt')
      File.write(path, 'SSRF ssrf enables admin and demonstrated full administrative control in this fixture.')
      evidence = { stored: path, path: path, sha256: Digest::SHA256.file(path).hexdigest, size: File.size(path) }
      rows = [{ id: 'ssrf', title: 'SSRF', severity: 'medium', verification_status: 'reproduced', enables: ['admin'] },
              { id: 'admin', title: 'Internal admin panel', severity: 'medium', verification_status: 'reproduced', chain_assessments: [
                { finding_ids: %w[ssrf admin], combined_severity: 'critical', rationale: 'Full administrative control through the SSRF.',
                  reproduction_steps: ['Send the SSRF request.', 'Observe internal administrative control.'], evidence_artifacts: [evidence] }
              ] }, { id: 'isolated', title: 'Isolated high', severity: 'high' }]
      payload = described_class.report_payload(results_hash: { findings: rows })
      expect(payload[:attack_chains].length).to eq(1)
      expect(payload[:attack_chains].first).to include(finding_ids: %w[ssrf admin], combined_severity: 'critical', assessment_status: 'evidence_backed', links: [{ from: 'ssrf', to: 'admin' }])
      expect(payload[:priorities].map { |item| item[:combined_severity] }).to eq(%w[critical high])
      expect(payload[:findings].first['severity']).to eq('medium')
      packaged = described_class.package_evidence(payload: payload, path: File.join(dir, 'report.json'))
      attachment = packaged[:attack_chains].first[:evidence_artifacts].first[:attachment]
      expect(attachment).to match(%r{\Aattachments/[a-f0-9]{64}\.bin\z})
      expect(Digest::SHA256.file(File.join(dir, attachment)).hexdigest).to eq(evidence[:sha256])
      expect(packaged[:priorities].first[:evidence_artifacts].first[:attachment]).to eq(attachment)
      File.write(path, 'tampered')
      expect { described_class.report_payload(results_hash: { findings: rows }) }.to raise_error(IOError, /integrity/)
    end
  end

  it 'packages durable evidence with normalized metadata for JSON and SARIF' do
    require 'tmpdir'
    require 'digest'
    Dir.mktmpdir do |dir|
      original = File.join(dir, 'original.pcap')
      stored = File.join(dir, 'stored')
      bytes = 'synthetic PCAP regression bytes'
      File.binwrite(original, bytes)
      File.binwrite(stored, bytes)
      File.unlink(original)
      artifact = { handle: 'artifact:test', kind: 'pcap', label: 'capture', path: original,
                   stored: stored, sha256: Digest::SHA256.hexdigest(bytes), size: bytes.bytesize }
      finding = { id: 'one', reproduction_steps: ['Run fixture'], severity_justification: 'Observed impact', evidence_artifacts: [artifact] }
      [PWN::Reports::JSON, PWN::Reports::SARIF].each do |writer|
        out = writer.generate(path: File.join(dir, "#{writer.name.split('::').last}.json"), results_hash: { findings: [finding] })
        doc = JSON.parse(File.read(out))
        row = doc['findings'] ? doc['findings'].first : doc['runs'].first['results'].first['properties']
        exported = row.fetch('evidence_artifacts').first
        expect(exported).to include(artifact.transform_keys(&:to_s))
        expect(exported.fetch('attachment')).to match(%r{\Aattachments/[a-f0-9]{64}\.pcap\z})
        expect(Digest::SHA256.file(File.join(dir, exported['attachment'])).hexdigest).to eq(artifact[:sha256])
        expect(row['reproduction_steps']).to eq(['Run fixture'])
      end
      expect(artifact).not_to have_key(:attachment)
    end
  end

  it 'preserves direction and branch-specific impact without promoting unrelated paths' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'combined.txt')
      File.write(path, 'Only the source -> admin -> impact branch achieves full control in this synthetic fixture.')
      evidence = { stored: path, sha256: Digest::SHA256.file(path).hexdigest, size: File.size(path) }
      rows = [{ id: 'source', severity: 'medium', enables: %w[admin other] },
              { id: 'admin', severity: 'medium', enables: ['impact'] },
              { id: 'other', severity: 'medium', enables: ['impact'] },
              { id: 'impact', severity: 'medium', combined_severity: 'critical', chain_assessments: [
                { finding_ids: %w[source admin impact], combined_severity: 'critical', rationale: 'Full control only through admin.', evidence_artifacts: [evidence] }
              ] }]
      chains = described_class.attack_chains(findings: rows.reverse)
      expect(chains.map { |chain| chain[:finding_ids] }).to eq([%w[source admin impact], %w[source other impact]])
      expect(chains.map { |chain| chain[:combined_severity] }).to eq(%w[critical medium])
      expect(chains.last[:assessment_status]).to eq('unassessed')
      rows.last[:enables] = ['source']
      expect { described_class.attack_chains(findings: rows) }.to raise_error(ArgumentError, /cycle/)
    end
  end

  it 'ignores cross-engagement edges and never upgrades links from titles or unscoped scores' do
    rows = [{ id: 'ssrf', title: 'SSRF', severity: 'medium', enables: ['admin'], engagement_id: 'alpha' },
            { id: 'admin', title: 'Internal admin takeover', severity: 'medium', combined_severity: 'critical', engagement_id: 'beta' }]
    expect(described_class.attack_chains(findings: rows)).to eq([])
    rows.last[:engagement_id] = 'alpha'
    expect(described_class.attack_chains(findings: rows).first).to include(combined_severity: 'medium', assessment_status: 'unassessed')
    rows.last[:enables] = ['admin']
    expect { described_class.attack_chains(findings: rows) }.to raise_error(ArgumentError, /cycle/)
  end

  it 'does not count isolated findings against the chain path limit' do
    rows = Array.new(1002) { |index| { id: "isolated-#{index}", severity: 'medium' } }
    expect(described_class.attack_chains(findings: rows)).to eq([])
  end

  it 'renders per-finding reproducibility and escaped portable evidence in HTML and Markdown' do
    Dir.mktmpdir do |dir|
      fixtures = { 'screenshot' => "\x89PNG\r\n\x1a\nsynthetic PNG fixture".b,
                   'pcap' => 'synthetic pcap', 'crash' => 'synthetic crash', 'poc' => 'synthetic PoC' }
      artifacts = fixtures.map do |kind, bytes|
        path = File.join(dir, kind)
        File.binwrite(path, bytes)
        { 'kind' => kind, label: '<script>fixture</script>', handle: "artifact:#{kind}",
          path: path, stored: path, sha256: Digest::SHA256.hexdigest(bytes), size: bytes.bytesize }
      end
      rows = [{ id: 'first', title: '<script>title</script>', reproduction_steps: ['Execute <fixture>', 'Observe result'],
                severity_justification: 'Measured <impact>', poc: "printf '<ok>'\n```\n<script>bad</script>", evidence_artifacts: artifacts },
              { id: 'second', title: 'Legacy finding' }]
      html = File.read(PWN::Reports::HTML.generate(path: File.join(dir, 'report.html'), results_hash: { findings: rows }))
      md = File.read(PWN::Reports::Markdown.generate(path: File.join(dir, 'report.md'), results_hash: { findings: rows }))
      expect(html).to include('<ol><li>Execute &lt;fixture&gt;</li><li>Observe result</li></ol>', '<h3>Severity justification</h3>', '<pre><code>', '<img src="attachments/')
      expect(html).not_to include('<script>')
      expect(md).to include('1. Execute &lt;fixture&gt;', '2. Observe result', '#### Severity justification', '````', '![')
      expect(md).to include('&lt;script&gt;title&lt;/script&gt;')
      [html, md].each do |text|
        artifacts.each do |artifact|
          expect(text).to include(artifact[:sha256], artifact[:size].to_s, artifact[:handle])
        end
        expect(text).to include('Not supplied')
      end
      expect(html.split('<section>').last).not_to include('artifact:screenshot')
      expect(md.split('### second').last).not_to include('artifact:screenshot')
    end
  end

  it 'rejects missing or altered evidence and tampered export targets explicitly' do
    Dir.mktmpdir do |dir|
      source = File.join(dir, 'source')
      stored = File.join(dir, 'durable')
      bytes = 'synthetic crash fixture'
      File.write(source, bytes)
      File.write(stored, bytes)
      artifact = { kind: 'crash', path: source, stored: stored, sha256: Digest::SHA256.hexdigest(bytes), size: bytes.bytesize }
      opts = { path: File.join(dir, 'report.json'), results_hash: { findings: [{ evidence_artifacts: [artifact] }] } }
      out = PWN::Reports::JSON.generate(opts)
      target = File.join(dir, JSON.parse(File.read(out))['findings'].first['evidence_artifacts'].first['attachment'])
      File.write(target, 'tampered')
      expect { PWN::Reports::JSON.generate(opts) }.to raise_error(IOError, /attachment integrity mismatch/)
      File.unlink(target)
      File.write(stored, 'tampered')
      expect { PWN::Reports::JSON.generate(opts) }.to raise_error(IOError, /integrity mismatch/)
      File.unlink(stored)
      expect { PWN::Reports::JSON.generate(opts) }.to raise_error(IOError, /missing/)
      File.write(stored, bytes)
      artifact[:size] += 1
      expect { PWN::Reports::JSON.generate(opts) }.to raise_error(IOError, /integrity mismatch/)
      artifact[:sha256] = 'abc'
      expect { PWN::Reports::JSON.generate(opts) }.to raise_error(ArgumentError, /full SHA-256/)
    end
  end

  it 'never inlines active screenshot content or trusts supplied attachment URLs' do
    Dir.mktmpdir do |dir|
      bytes = '<svg onload="alert(1)"></svg>'
      source = File.join(dir, 'unsafe.png')
      File.write(source, bytes)
      artifact = { kind: 'screenshot', label: '"](<script>)', path: source, stored: source, sha256: Digest::SHA256.hexdigest(bytes),
                   size: bytes.bytesize, attachment: 'javascript:alert(1)', inline_image: true }
      opts = { results_hash: { findings: [{ evidence_artifacts: [artifact] }] }, dir_path: dir, report_name: 'safe' }
      html = File.read(PWN::Reports::HTML.generate(opts))
      md = File.read(PWN::Reports::Markdown.generate(opts))
      expect(html).not_to include('<img', 'javascript:', '<script>')
      expect(md).not_to include('![', 'javascript:', '<script>')
      expect(html).to include("attachments/#{artifact[:sha256]}.bin")
      expect(md).to include("attachments/#{artifact[:sha256]}.bin")
    end
  end

  it 'requires durable storage even when an original source still exists' do
    Dir.mktmpdir do |dir|
      source = File.join(dir, 'source')
      File.write(source, 'fixture')
      artifact = { path: source, sha256: Digest::SHA256.hexdigest('fixture'), size: 7 }
      [nil, '', File.join(dir, 'absent')].each do |stored|
        artifact[:stored] = stored
        expect do
          PWN::Reports::JSON.generate(path: File.join(dir, 'report.json'), results_hash: { findings: [{ evidence_artifacts: [artifact] }] })
        end.to raise_error(IOError, /missing/)
      end
      artifact.delete(:stored)
      expect do
        PWN::Reports::JSON.generate(path: File.join(dir, 'report.json'), results_hash: { findings: [{ evidence_artifacts: [artifact] }] })
      end.to raise_error(IOError, /missing/)
    end
  end

  it 'bounds inline PoC text while exporting the complete non-executed script' do
    Dir.mktmpdir do |dir|
      code = "raise 'NEVER EXECUTE'\n#{'x' * 20_000}END_OF_SCRIPT"
      finding = { id: 'poc', poc: code, severity_justification: 'fixture only' }
      opts = { results_hash: { findings: [finding] }, dir_path: dir, report_name: 'bounded' }
      [PWN::Reports::HTML, PWN::Reports::Markdown].each do |writer|
        text = File.read(writer.generate(opts))
        expect(text).to include('Preview truncated', Digest::SHA256.hexdigest(code))
        expect(text).not_to include('END_OF_SCRIPT')
      end
      row = JSON.parse(File.read(PWN::Reports::JSON.generate(opts)))['findings'].first
      expect(row['poc']).to eq(code)
      attachment = row.fetch('poc_export')
      expect(File.binread(File.join(dir, attachment.fetch('attachment')))).to eq(code)
      expect(attachment).to include('sha256' => Digest::SHA256.hexdigest(code), 'size' => code.bytesize)
    end
  end

  it 'should return data for help method' do
    help_response = PWN::Reports.help
    expect(help_response).not_to be_nil
  end
end
