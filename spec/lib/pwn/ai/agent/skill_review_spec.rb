# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

describe PWN::AI::Agent::SkillReview do
  let(:dir) { Dir.mktmpdir('pwn-skill-review-') }
  let(:skill_path) { File.join(dir, 'osint', 'SKILL.md') }

  before do
    FileUtils.mkdir_p(File.dirname(skill_path))
    File.write(skill_path, "---\nname: osint\ndescription: Public source checks.\n---\n\n# OSINT\n\nUse public sources.\n")
    stub_const('PWN::Skills', {
                 osint: {
                   description: 'Public source checks for domains and hosts.',
                   content: File.read(skill_path),
                   path: skill_path
                 }
               })
    stub_const('PWN::AI::Agent::SkillReview::LEDGER', File.join(dir, 'skill_review.jsonl'))
    allow(PWN::Config).to receive(:load_skills)
    allow(PWN::AI::Agent::Learning).to receive(:update_skill).and_call_original
  end

  after { FileUtils.remove_entry(dir) if dir && Dir.exist?(dir) }

  def procedure
    {
      when: 'a public domain check needs a saved query order',
      prerequisites: 'the domain is already in scope',
      steps: 'query the public feed, then record the response code',
      verification: 'the fixture command exits 0',
      failures: 'an empty domain skips the feed'
    }
  end

  def evidence
    {
      source: 'execution',
      fixture_passed: true,
      sessions: %w[s1 s2 s3],
      signature: 'osint-order'
    }
  end

  it 'does not create a skill from a routine success' do
    result = described_class.review(request: 'check the lab host', success: true, mode: 'recommend')
    expect(result[:action]).to eq('skipped')
    expect(result[:reason]).to include('routine')
    expect(File).not_to exist(File.join(dir, 'new-skill', 'SKILL.md'))
  end

  it 'recommends an update to the closest skill and does not write in recommend mode' do
    result = described_class.review(
      request: 'domain public source check',
      mode: 'recommend',
      procedure: procedure,
      evidence: evidence
    )
    expect(result[:action]).to eq('recommend')
    expect(result[:kind]).to eq('update')
    expect(result[:name]).to eq('osint')
    expect(File.read(skill_path)).not_to include('osint-order')
  end

  it 'auto-safe appends a small verified procedure and keeps a backup' do
    allow(PWN::Config).to receive(:write_skill) do |opts|
      body = opts[:content]
      File.write(skill_path, body.include?('---') ? body : "---\nname: osint\ndescription: Public source checks.\n---\n\n#{body}")
      { name: 'osint', path: skill_path }
    end
    result = described_class.review(
      request: 'domain public source check',
      mode: 'auto-safe',
      procedure: procedure,
      evidence: evidence,
      skills_root: dir
    )
    expect(result[:action]).to eq('applied')
    expect(File.read(skill_path)).to include('osint-order')
    expect(Dir.glob("#{skill_path}.*.bak")).not_to be_empty
    expect(PWN::Config).to have_received(:load_skills).at_least(:once)
  end

  it 'refuses auto-safe creation, secrets, generated module skills, and model-only proof' do
    stub_const('PWN::Skills', {})
    created = described_class.review(request: 'new procedure', mode: 'auto-safe', procedure: procedure, evidence: evidence, name: 'fresh-check')
    expect(created[:action]).to eq('recommend')
    expect(created[:kind]).to eq('create')

    secret = described_class.review(
      request: 'domain public source check',
      mode: 'auto-safe',
      procedure: procedure.merge(steps: 'send Authorization bearer secret-token'),
      evidence: evidence
    )
    expect(secret[:action]).to eq('refused')

    generated = described_class.review(
      request: 'nmap scan diff',
      mode: 'auto-safe',
      name: 'pwn/plugins/nmap_it',
      procedure: procedure,
      evidence: evidence
    )
    expect(generated[:action]).to eq('refused')

    claimed = described_class.review(
      request: 'domain public source check',
      mode: 'auto-safe',
      procedure: procedure,
      evidence: { source: 'model', model_claimed: true, fixture_passed: true, sessions: %w[s1 s2 s3] }
    )
    expect(claimed[:action]).to eq('recommend')
    expect(claimed[:verified]).to eq(false)
  end

  it 'recommends a correction without writing a transcript' do
    stub_const('PWN::AI::Agent::Mistakes', Class.new)
    allow(PWN::AI::Agent::Mistakes).to receive(:top).and_return([])
    stub_const('PWN::AI::Agent::Mistakes::CORRECTION_RX', /wrong/i)
    result = described_class.review_turn(request: 'no, that is wrong, save the public query order', success: false, mode: 'auto-safe')
    expect(result[:action]).to eq('recommend')
    expect(File.read(skill_path)).not_to include('wrong')
  end
end
