# frozen_string_literal: true

require 'spec_helper'
require 'digest'

RSpec.describe 'PWN::AI::Sandbox mandatory write-grant review' do
  include_context 'pwn tmp sandbox'

  before do
    @home = File.join(@tmp, 'home')
    @work = File.join(@tmp, 'work')
    @outputs = File.join(@tmp, 'outputs')
    @source = File.join(@outputs, 'source')
    @state = File.join(@outputs, 'controller-artifacts')
    FileUtils.mkdir_p([@home, @work, @source, @state])
    allow(Dir).to receive(:home).and_return(@home)
    allow(PWN::AI::Sandbox).to receive(:protected_roots).and_return([@source, '/opt/pwn'])
    stub_const('PWN::Plugins::ArtifactRegistry::ROOT', @state)
    @saved_runtime = Thread.current[:pwn_request_runtime]
    @source_file = File.join(@source, 'sentinel')
    @state_file = File.join(@state, 'sentinel')
    File.write(@source_file, 'original-source')
    File.write(@state_file, 'original-state')
  end

  after do
    Thread.current[:pwn_request_runtime] = @saved_runtime
  end

  def dispatch_boundary(request, &handler)
    runtime = PWN::AI::Agent::RequestRuntime.new(request: request, session_id: 'sandbox-review', artifact_root: File.join(@tmp, 'request-state'), cwd: @work, trace: false, retrieve: false)
    Thread.current[:pwn_request_runtime] = runtime
    PWN::AI::Agent::Registry.register(name: 'sandbox_pbr01_boundary', toolset: 'fixture', schema: { name: 'sandbox_pbr01_boundary', parameters: { type: 'object' } }, handler: handler)
    row = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'sandbox_pbr01_boundary', arguments: '{}' } }))
    [row, runtime]
  end

  def permitted_operation
    yield
    'allowed'
  rescue Errno::EACCES, Errno::EPERM, Errno::EXDEV
    'denied'
  end

  it 'lets a worker maintain ordinary documents in the named skills library, not its parent', :requires_landlock do
    library = File.join(@home, '.pwn', 'skills')
    other = File.join(File.dirname(library), 'elsewhere.txt')
    entry = File.join(library, 'meeting-notes', 'SKILL.md')
    reference = File.join(File.dirname(entry), 'references', 'format.txt')
    row, = dispatch_boundary("Save the meeting notes skill under #{library}") do |_args|
      FileUtils.mkdir_p(File.dirname(reference))
      File.write(entry, "# Meeting notes\n")
      draft = "#{reference}.draft"
      File.write(draft, 'first')
      File.rename(draft, reference)
      File.write(reference, 'Date and decisions')
      File.write(draft, 'discard')
      File.unlink(draft)
      { saved: File.read(reference), outside: permitted_operation { File.write(other, 'unexpected') } }
    end
    expect(row.dig('result', 'saved')).to eq('Date and decisions'), row.inspect
    expect(row.dig('result', 'outside')).to eq('denied')
    expect(File.read(entry)).to eq("# Meeting notes\n")
    expect(File.binread(reference)).to eq('Date and decisions')
    expect(File).not_to exist("#{reference}.draft")
    expect(File).not_to exist(other)
  end

  it 'grants the named reference file, not its neighbors or permission to create links', :requires_landlock do
    skill = File.join(@home, '.pwn', 'skills', 'meeting-notes')
    entry = File.join(skill, 'SKILL.md')
    reference = File.join(skill, 'references', 'format.md')
    neighbor = File.join(File.dirname(reference), 'calendar.md')
    FileUtils.mkdir_p(File.dirname(reference))
    File.write(entry, '# Original')
    File.write(neighbor, 'keep')
    stub_const('PWN::Skills', { notes: { path: entry } })
    row, = dispatch_boundary("Write the supporting document to #{reference}") do |_args|
      File.write(reference, 'Meeting date')
      { neighbor: permitted_operation { File.write(neighbor, 'changed') }, entry: permitted_operation { File.write(entry, 'changed') },
        link: permitted_operation { File.symlink('format.md', "#{reference}.link") } }
    end
    expect(row.fetch('result')).to eq('neighbor' => 'denied', 'entry' => 'denied', 'link' => 'denied')
    expect(File.binread(reference)).to eq('Meeting date')
    expect(File.binread(neighbor)).to eq('keep')
    expect(File.binread(entry)).to eq('# Original')
    expect(File).not_to exist("#{reference}.link")
  end

  it 'creates a missing named package directory without granting its parent', :requires_landlock do
    library = File.join(@home, '.pwn', 'skills')
    dir = File.join(library, 'new-guide')
    entry = File.join(dir, 'SKILL.md')
    other = File.join(library, 'other.md')
    row, = dispatch_boundary("Save the notes under #{dir}/") do |_args|
      FileUtils.mkdir_p(dir)
      File.write(entry, 'notes')
      { outside: permitted_operation { File.write(other, 'other') } }
    end
    expect(row.dig('result', 'outside')).to eq('denied'), row.inspect
    expect(File.binread(entry)).to eq('notes')
    expect(File).not_to exist(other)
  end

  it 'keeps stored skills unchanged on a read-only request, including delegated write requests', :requires_landlock do
    prior = Thread.current[:pwn_loop_nested]
    document = File.join(@home, '.pwn', 'skills', 'calendar.md')
    FileUtils.mkdir_p(File.dirname(document))
    File.write(document, 'original')
    check = ->(_args) { { outcome: permitted_operation { File.write(document, 'changed') } } }
    row, = dispatch_boundary("Read #{document}", &check)
    expect(row.dig('result', 'outcome')).to eq('denied')
    Thread.current[:pwn_loop_nested] = true
    row, = dispatch_boundary("Write to #{document}", &check)
    expect(row.dig('result', 'outcome')).to eq('denied')
    expect(File.binread(document)).to eq('original')
  ensure
    Thread.current[:pwn_loop_nested] = prior
  end

  it 'does not turn a negation, copy source, or standalone practice prompt into a skill write grant', :requires_landlock do
    prior = Thread.current[:pwn_curriculum]
    file = File.join(@home, '.pwn', 'skills', 'notes.md')
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, 'keep')
    check = ->(_args) { { outcome: permitted_operation { File.write(file, 'changed') } } }
    ["Do not edit #{file}; just describe it", "Copy #{file} to #{File.join(@work, 'copy.md')}"].each do |request|
      row, = dispatch_boundary(request, &check)
      expect(row.dig('result', 'outcome')).to eq('denied'), row.inspect
    end
    Thread.current[:pwn_curriculum] = true
    row, = dispatch_boundary("Write to #{file}", &check)
    expect(row.dig('result', 'outcome')).to eq('denied'), row.inspect
    expect(File.binread(file)).to eq('keep')
  ensure
    Thread.current[:pwn_curriculum] = prior
  end

  it 'keeps distinct configured and directly loaded catalog roots protected', :requires_landlock do
    library = File.join(@home, '.pwn', 'skills')
    alternate = File.join(library, 'separate')
    external = File.join(@home, 'other-library')
    FileUtils.mkdir_p(alternate)
    stub_const('PWN::Env', { pwn_skills_path: alternate })
    stub_const('PWN::Skills', {})
    PWN::Config.load_skills(pwn_skills_path: external)
    [alternate, external].each do |root|
      path = File.join(root, 'new.md')
      row, = dispatch_boundary("Write to #{path}") do |_args|
        { outcome: permitted_operation { File.write(path, 'note') } }
      end
      expect(row.dig('result', 'outcome')).to eq('denied'), row.inspect
      expect(File).not_to exist(path)
    end
  end

  it 'pins an ordinary named output without granting a protected hardlink in the same directory', :requires_landlock do
    linked = File.join(@work, 'linked.md')
    output = File.join(@work, 'receipt.txt')
    File.link(@source_file, linked)
    row, = dispatch_boundary("Write the receipt to #{output}") do |_args|
      File.write(output, 'saved')
      { linked: permitted_operation { File.write(linked, 'changed') } }
    end
    expect(row.dig('result', 'linked')).to eq('denied'), row.inspect
    expect(File.binread(output)).to eq('saved')
    expect(File.binread(@source_file)).to eq('original-source')
  end

  it 'does not grant a skill directory containing a linked file or a controller store', :requires_landlock do
    library = File.join(@home, '.pwn', 'skills')
    FileUtils.mkdir_p(library)
    linked = File.join(library, 'linked.md')
    File.link(@source_file, linked)
    check = ->(_args) { { outcome: permitted_operation { File.write(linked, 'changed') } } }
    row, = dispatch_boundary("Save notes in #{library}", &check)
    expect(row.dig('result', 'outcome')).to eq('denied')
    expect(File.binread(@source_file)).to eq('original-source')

    File.unlink(linked)
    File.write(linked, 'controller data')
    stub_const('PWN::Memory::MEMORY_FILE', linked)
    row, = dispatch_boundary("Save notes in #{library}", &check)
    expect(row.dig('result', 'outcome')).to eq('denied')
    expect(File.binread(linked)).to eq('controller data')
  end

  it 'does not extend a skills grant across a mounted directory', :requires_landlock do
    library = File.join(@home, '.pwn', 'skills')
    shared = File.join(library, 'shared notes')
    FileUtils.mkdir_p(shared)
    # An existing bind mount can look like an ordinary directory on the same device.
    record = "123 100 0:1 /notes #{shared.gsub(' ') { '\\040' }} rw - tmpfs tmpfs rw\n"
    allow(File).to receive(:readlines).and_call_original
    allow(File).to receive(:readlines).with('/proc/self/mountinfo').and_return([record])
    row, = dispatch_boundary("Save the notes under #{library}") do |_args|
      { outcome: permitted_operation { File.write(File.join(shared, 'note.txt'), 'note') } }
    end
    expect(row.dig('result', 'outcome')).to eq('denied')
    expect(Dir.children(shared)).to be_empty
  end

  it '[PBR-01] denies source and controller writes despite an original-request sibling output', :aggregate_failures do
    output = File.join(@outputs, 'requested.txt')
    reason = PwnSpecLandlock.unavailable_reason
    # Setup can pin a named file before worker admission. Check its contents,
    # not its existence, to detect an unauthorized handler write.
    File.write(output, 'untouched') if reason
    before = [@source_file, @state_file].to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
    row, runtime = dispatch_boundary("Write the report to #{output}") do |_args|
      attempts = [@source_file, @state_file].map do |path|
        File.write(path, 'modified')
        'allowed'
      rescue Errno::EACCES, Errno::EPERM
        'denied'
      end
      File.write(output, 'named')
      { attempts: attempts, named: File.read(output) }
    end
    expect(runtime.contract[:required_artifacts]).to eq([output])
    expect([@source_file, @state_file].to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }).to eq(before)
    if reason
      expect(row).to include('success' => false, 'result' => include('execution_state' => 'not_started', 'error' => "repository protection: #{reason}"))
      expect(File.read(output)).to eq('untouched')
    else
      expect(row.dig('result', 'attempts')).to eq(%w[denied denied])
      expect(row.dig('result', 'named')).to eq('named')
      expect(File.read(output)).to eq('named')
    end
  end
end
