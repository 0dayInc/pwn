# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Reward, 'structured result envelopes' do
  it 'classifies pretty printed JSON the same as compact JSON' do
    raw = JSON.pretty_generate(success: true, result: { exit: 0, stdout: 'fixture', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(ok: true, semantic_ok: true, exit: 0)
  end

  it 'does not borrow a nested success flag for a failed dispatch' do
    raw = JSON.generate(success: false, error: 'dispatch failed', result: { success: true })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(ok: false, semantic_ok: false)
  end

  it 'recognizes negative exits rather than treating them as absent' do
    raw = JSON.generate(success: true, result: { exit: -1, stdout: '', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(semantic_ok: false, exit: -1)
  end

  it 'does not classify observed timeout and invalid_payload text as an execution error' do
    raw = JSON.generate(success: true, result: { exit: 0, stdout: 'documentation: timeout after 20s invalid_payload', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: "shell → #{raw}")).to include(semantic_ok: true)
  end

  it 'does not accept an explicitly failed nested result' do
    raw = JSON.generate(success: true, result: { success: false, error: 'fixture failure' })
    expect(described_class.semantic_ok(name: 'pwn_eval', raw: raw)).to include(ok: true, semantic_ok: false)
  end

  it 'does not treat a nested informational_exit flag as a dispatch envelope marker' do
    raw = JSON.generate(success: false, result: { exit: 1, informational_exit: true, stdout: '', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(semantic_ok: false, benign: false, shape: :nonzero_exit)
  end

  it 'does not let an envelope informational_exit launder a nested false result' do
    raw = JSON.generate(success: false, informational_exit: true, result: { exit: 1, success: false, stdout: '', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(semantic_ok: false, benign: false)
  end

  it 'keeps a dispatch envelope informational_exit benign without argv' do
    raw = JSON.generate(success: false, informational_exit: true, result: { exit: 1, stdout: '', stderr: '' })
    expect(described_class.semantic_ok(name: 'shell', raw: raw)).to include(ok: false, semantic_ok: true, benign: true, shape: nil)
  end
end
