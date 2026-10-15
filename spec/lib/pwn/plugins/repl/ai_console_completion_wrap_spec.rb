# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'pry'

describe 'mission completion wrapping' do
  let(:console) { PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil) }
  let(:paint) { [] }
  let(:screen) { double('completion screen') }

  before do
    allow(screen).to receive(:attron) { |*, &block| block.call }
    console.instance_variable_set(:@screen, screen)
    console.instance_variable_set(:@width, 80)
    console.instance_variable_set(:@height, 30)
    console.instance_variable_set(:@compose_height, 5)
    console.instance_variable_set(:@footer_height, 3)
    console.instance_variable_set(:@menu_index, 0)
    allow(console).to receive(:tone) { |role| role }
    allow(console).to receive(:put) { |*args| paint << args }
  end

  it 'wraps a real filesystem completion without altering its suffix or grapheme cursor' do
    Dir.mktmpdir('completion-wrap') do |root|
      path = File.join(root, "#{'directory-' * 12}界é.txt")
      File.write(path, 'offline fixture')
      prefix = "inspect #{root}/dir"
      editor = console.instance_variable_get(:@editor)
      editor.place("#{prefix} suffix", prefix.scan(/\X/).length)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      console.refresh_completion
      item = console.instance_variable_get(:@menu).first
      expect(item[:label]).to eq(path)
      console.draw_menu
      expect(paint.select { |row| row[3] == :selection }.map { |row| row[2][2..].rstrip }.join).to eq(path)
      console.accept_completion
      expect([editor.text, editor.cursor]).to eq([item[:text], item[:cursor]])
      expect(editor.text).to end_with(' suffix')
    end
  end

  it 'reflows on resize and filtering, bounds the overlay above dynamic chrome and tracks candidates not rows' do
    items = Array.new(12) { |index| { label: "PWN::#{'LongNamespace::' * 8}Module#{index}", text: "payload#{index}", cursor: 3 } }
    console.instance_variable_set(:@menu, items)
    wide = console.completion_layout
    expect(wide[:top] + wide[:height]).to eq(22)
    console.instance_variable_set(:@width, 48)
    console.instance_variable_set(:@height, 14)
    console.instance_variable_set(:@compose_height, 3)
    console.instance_variable_set(:@footer_height, 4)
    narrow = console.completion_layout
    expect(narrow[:rows].length).to be > wide[:rows].length
    expect(narrow.values_at(:top, :height)).to eq([0, 7])
    editor = console.instance_variable_get(:@editor)
    editor.place('draft界', 3)
    console.handle(:down)
    console.draw_menu
    expect(console.instance_variable_get(:@menu_index)).to eq(1)
    expect([editor.text, editor.cursor]).to eq(['draft界', 3])
    expect(console).to receive(:complete)
    console.handle("\t")
    expect([editor.text, editor.cursor]).to eq(['payload1', 3])
    console.instance_variable_set(:@menu, [{ label: 'short', text: 'short', cursor: 5 }])
    console.instance_variable_set(:@menu_index, 0)
    expect(console.completion_layout.values_at(:height, :top)).to eq([3, 4])
    console.handle("\e")
    expect(console.instance_variable_get(:@menu)).to be_nil
  end

  it 'pages an oversized candidate without moving selection, draft or transcript scroll' do
    label = "PWN::#{'Namespace::' * 100}Tail"
    console.instance_variable_set(:@menu, [{ label: label, text: label, cursor: label.length }])
    console.instance_variable_set(:@height, 14)
    console.instance_variable_set(:@width, 48)
    console.instance_variable_set(:@scroll, 17)
    console.draw_menu
    seen = []
    20.times do
      seen.concat(paint.select { |row| row[3] == :selection }.map { |row| row[2] })
      paint.clear
      console.handle(:page_down)
      console.draw_menu
    end
    expect(seen.join).to include('Tail')
    expect(console.instance_variable_get(:@menu_index)).to eq(0)
    expect(console.instance_variable_get(:@scroll)).to eq(17)
    expect(console.instance_variable_get(:@editor).text).to eq('')
    console.handle(:page_up)
    paint.clear
    console.draw_menu
    expect(paint.select { |row| row[3] == :selection }.map { |row| row[2] }.join).not_to include('Tail')
  end

  it 'renders every grapheme of a long path on multiple selected visual rows without changing insertion' do
    label = "/tmp/#{'界é/long-directory/' * 8}last.txt"
    item = { label: label, text: "read #{label} trailing", cursor: 9 }
    console.instance_variable_set(:@menu, [item])
    console.draw_menu
    rows = paint.select { |row| row[1] == 4 && row[3] == console.tone(:selection) }
    expect(rows.map { |row| row[2][2..].rstrip }.join).to eq(label)
    expect(rows.length).to be > 1
    expect(rows.map { |row| console.width(row[2]) }.uniq).to eq([61])
    expect(screen).to have_received(:attron).with(Curses::A_REVERSE).exactly(rows.length).times
    expect(console).to receive(:complete)
    console.accept_completion
    editor = console.instance_variable_get(:@editor)
    expect([editor.text, editor.cursor]).to eq([item[:text], 9])
  end
end
