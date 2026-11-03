# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::REPL::AIConsole::VaultEdit, 'YAML scalar fidelity' do
  it 'preserves colon-prefixed lines inside nested mapping and array values' do
    value = { setting: "before\n:leading-colon\nafter\n", rows: [{ text: "line\n:other: value\n" }] }
    editor = described_class.allocate
    expect(editor.parse(editor.serialize(value))).to eq(value)
  end
end
