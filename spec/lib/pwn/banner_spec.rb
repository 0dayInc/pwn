# frozen_string_literal: true

require 'spec_helper'

describe PWN::Banner do
  def block_colors(rows)
    rows.flat_map do |row|
      [0, 2].map do |bit|
        row.chars.map do |pixel|
          glyph, foreground, background = described_class::MINI_PIXELS.fetch(pixel)
          mask = ' ▘▝▀▖▌▞▛▗▚▐▜▄▙▟█'.index(glyph)
          mask[bit] == 1 ? foreground : background || :black
        end
      end
    end
  end

  it 'packs every rotation losslessly beside different colors, holes and white flashes' do
    described_class::MINI_SHAPES.each_with_index do |shape, type|
      described_class.send(:mini_rotations, shape: shape).each do |rotation|
        [0, 1].each do |offset|
          source = Array.new(8) { 'cmywgrb '.dup }
          rotation.each { |x, y| source[y + offset][x + 2] = 'cymbrgg'[type] }
          packed = described_class.send(:mini_block_board, board: source)
          expected = source.map { |row| row.chars.map { |pixel| pixel == ' ' ? :black : described_class::MINI_PIXELS.fetch(pixel)[1] } }
          expect(block_colors(packed)).to eq(expected)
        end
      end
    end
  end

  it 'keeps every active tetromino color beside the stack throughout its fall and lock' do
    rotations = Hash.new { |hash, key| hash[key] = [] }
    [5, 8, 16, 20].product([1, 73, 74]).each do |size, seed|
      args = { name: :falling_blocks, width: size, height: size, seed: seed }
      frames = described_class.send(:mini_replay, **args)
      frames.each_with_index do |frame, index|
        next unless frame[:state][:active]

        points = frame[:state][:active]
        type = frame[:state][:type]
        cells = described_class.mini_cells(**args, frame: index)
        color = %i[cyan yellow magenta blue red green green][type]
        expected = frame[:state][:stack].map { |row| row.chars.map { |pixel| pixel == ' ' ? :black : described_class::MINI_PIXELS.fetch(pixel)[1] } }
        points.each { |x, y| expected[y][x] = color }
        expect(block_colors(frame[:rows].drop(1))).to eq(expected)
        points.each do |x, y|
          cell = cells[1 + (y / 2)][x]
          mask = ' ▘▝▀▖▌▞▛▗▚▐▜▄▙▟█'.index(cell[:glyph])
          actual = mask[(y % 2) * 2] == 1 ? cell[:foreground] : cell[:background]
          expect(actual).to eq(color)
        end
        next unless frames[index + 1][:event] == :lock

        expect(frames[index + 1][:rows]).to eq(frame[:rows])
        expect(described_class.mini_cells(**args, frame: index + 1)).to eq(cells)
        rotations[type] << points.map { |x, y| [x - points.map(&:first).min, y - points.map(&:last).min] }.sort
      end
    end
    described_class::MINI_SHAPES.each_with_index do |shape, type|
      expected = described_class.send(:mini_rotations, shape: shape).map(&:sort).uniq
      expect(rotations[type].uniq).to match_array(expected)
    end
  end

  it 'changes only completed rows to white on clear and preserves survivor colors on collapse' do
    frames = described_class.send(:mini_replay, name: :falling_blocks, width: 8, height: 8, seed: 73)
    clears = 0
    frames.each_cons(2) do |before, after|
      next unless after[:event] == :clear && before[:event] == :lock

      expected = block_colors(before[:rows].drop(1))
      after[:state][:lines].each { |y| expected[y] = Array.new(8, :white) }
      expect(block_colors(after[:rows].drop(1))).to eq(expected)
      clears += 1
    end
    expect(clears).to be_positive
    frames.each_cons(2) do |before, after|
      next unless before[:event] == :clear && after[:event] == :collapse

      lines = before[:state][:lines]
      survivors = block_colors(before[:rows].drop(1)).each_with_index.filter_map { |row, y| row unless lines.include?(y) }
      expect(block_colors(after[:rows].drop(1))).to eq(Array.new(lines.length) { Array.new(8, :black) } + survivors)
    end
  end

  it 'lands blocks on both bottom quadrants and spans the full board width' do
    [5, 8, 16, 20].each do |size|
      frames = described_class.send(:mini_replay, name: :falling_blocks, width: size, height: size, seed: 73)
      locks = frames.select { |frame| frame[:event] == :lock }
      expect(locks.first[:rows].last.chars.any? { |pixel| pixel != ' ' && ((pixel.ord - 256) % 16) & 12 != 0 }).to be(true)
      [0, size - 1].each do |column|
        expect(locks.any? { |frame| frame[:rows].drop(1).any? { |row| row[column] != ' ' } }).to be(true)
      end
      cells = described_class.mini_cells(name: :falling_blocks, width: size, height: size, frame: 100)
      expect(cells.length).to eq(size)
      expect(cells.map(&:length)).to all(eq(size))
    end
  end

  it 'packs blocks into two quadrants and snake segments into one without losing ink' do
    %i[falling_blocks snake].product((5..16).to_a).each do |name, size|
      frames = described_class.send(:mini_replay, name: name, width: size, height: size, seed: 73)
      frames.each do |frame|
        pixels = frame[:rows].drop(1).join.chars.reject { |pixel| pixel == ' ' }
        expect(pixels).to all(satisfy { |pixel| pixel.ord >= 256 })
        area = pixels.sum { |pixel| ((pixel.ord - 256) % 16).digits(2).sum }
        state = frame[:state]
        expected = if state[:body]
                     state[:body].length + (state[:food] ? 1 : 0)
                   elsif state[:active]
                     (state[:stack].sum { |row| row.count('^ ') } + 4) * 2
                   end
        expect(area).to eq(expected) if expected
        expect(frame[:rows].length).to eq(size)
        expect(frame[:rows].map(&:length)).to all(eq(size))
        expect(frame[:rows].first).to eq('PWN'.center(size))
      end
    end
  end

  it 'keeps snake food legible without erasing shared-cell quadrants' do
    # Head, body and food may share a character cell, but never lose occupied
    # quadrants. Food wins its cell's color; yellow head wins over green body.
    rows = described_class.send(:mini_quarter_board, board: ['gyf  ', '     ', '     ', '     '], name: 'snake')
    expect(described_class::MINI_PIXELS.fetch(rows[1][1])).to eq(['▀', :yellow])
    expect(described_class::MINI_PIXELS.fetch(rows[1][2])).to eq(['▘', :red])
  end

  it 'draws a tiny connected five-pixel arrowhead rather than a chunky rotating blob' do
    8.times do |direction|
      frames = []
      described_class.send(:mini_asteroids_snapshot, frames: frames, width: 8, height: 7, ship: [4, 3, direction * Math::PI / 4], thrust: false, rocks: [], shots: [], sparks: [])
      points = []
      frames.first[:rows].drop(1).each_with_index do |row, y|
        row.chars.each_with_index do |pixel, x|
          next if pixel == ' '

          mask = (pixel.ord - 256) % 16
          4.times { |bit| points << [(x * 2) + (bit % 2), (y * 2) + (bit / 2)] if mask[bit] == 1 }
        end
      end
      expect(points.length).to eq(5)
      expect(points.map(&:first).minmax.then { |a, b| b - a }).to eq(2)
      expect(points.map(&:last).minmax.then { |a, b| b - a }).to eq(2)
      connected = [points.shift]
      loop do
        adjacent = points.select { |point| connected.any? { |other| point.zip(other).all? { |a, b| (a - b).abs <= 1 } } }
        break if adjacent.empty?

        connected.concat(adjacent)
        points -= adjacent
      end
      expect(points).to be_empty
    end
  end

  it 'offers seeded Asteroids with rotating thrust, wrapped drift, shots and real breakups' do
    expect(described_class.mini_names).to include(:asteroids)
    expect(described_class.mini_frame_seconds(name: :asteroids)).to eq(0.05)
    (5..16).each do |size|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: 73)
      states = frames.filter_map { |frame| frame[:state] if frame[:state][:ship] }
      expect(frames.map { |frame| frame[:event] }).to include(:hit, :respawn)
      expect(states.map { |state| state[:thrust] }.uniq).to contain_exactly(true, false)
      expect(states.map { |state| state[:ship][2].round(1) }.uniq.length).to be > 12
      expect(states.map { |state| state[:shots].length }.max).to be_between(1, 2)
      expect(states.map { |state| state[:rocks].length }.max).to be <= [3, size / 4].min + 1
      expect(states.flat_map { |state| state[:rocks].map { |rock| rock[4] } }).to include(0.2, 0.5)
      states.each_cons(2) do |a, b|
        expect((((b[:ship][0] - a[:ship][0] + (size / 2.0)) % size) - (size / 2.0)).abs).to be <= 0.16
        a[:rocks].each do |rock|
          next_rock = b[:rocks].find { |candidate| candidate[5] == rock[5] }
          next unless next_rock

          expect(next_rock[0]).to be_within(0.000001).of((rock[0] + rock[2]) % size)
          expect(next_rock[1]).to be_within(0.000001).of((rock[1] + rock[3]) % (size - 1))
        end
      end
    end
  end

  it 'keeps rocks small and neutral with sparse quarter-cell shots and thrust' do
    frames = []
    described_class.send(:mini_asteroids_snapshot, frames: frames, width: 8, height: 7, ship: [4, 3, 0], thrust: false,
                                                   rocks: [[1, 1, 0, 0, 0.5, 1]], shots: [], sparks: [])
    rock_pixels = frames.first[:rows].drop(1).flat_map(&:chars).reject { |pixel| pixel == ' ' || (pixel.ord - 256) / 16 == 0 }
    expect(rock_pixels.map { |pixel| described_class::MINI_PIXELS.fetch(pixel)[1] }.uniq).to eq([:white])
    expect(rock_pixels.sum { |pixel| ((pixel.ord - 256) % 16).digits(2).sum }).to eq(4)
  end

  it 'keeps a readable five-pixel ship and sparse subcell occupancy throughout tiny seeded replays' do
    [5, 8, 16].product([1, 73, 74]).each do |size, seed|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: seed)
      frames.each do |frame|
        next unless frame[:state][:ship]

        pixels = frame[:rows].drop(1).flat_map(&:chars).reject { |pixel| pixel == ' ' }
        area = pixels.sum { |pixel| ((pixel.ord - 256) % 16).digits(2).sum }
        ship = pixels.select { |pixel| (pixel.ord - 256) / 16 == 0 }
        expect(ship.sum { |pixel| ((pixel.ord - 256) % 16).digits(2).sum }).to eq(5)
        expect(area).to be <= [20, size * (size - 1)].min
        # A lone quadrant can occupy a cell: measure ink area above, not full
        # character rectangles, while bounding the number of colored cells too.
        expect(pixels.length).to be <= 14
      end
    end
  end

  it 'spawns rocks clear of the ship instead of starting with overlapping sprites' do
    [5, 8, 16].product([1, 73, 74]).each do |size, seed|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: seed)
      state = frames.find { |frame| frame[:state][:ship] }[:state]
      state[:rocks].each do |rock|
        dx = described_class.send(:mini_delta, from: state[:ship][0], to: rock[0], span: size)
        dy = described_class.send(:mini_delta, from: state[:ship][1], to: rock[1], span: size - 1)
        expect((dx * dx) + (dy * dy)).to be > 1.3**2
      end
    end
  end

  it 'keeps red exhaust visible behind the cyan hull rather than erasing it in shared cells' do
    [5, 8, 16].each do |size|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: 73)
      thrust = frames.select { |frame| frame[:state][:thrust] }
      visible = thrust.count { |frame| frame[:rows].drop(1).join.chars.any? { |pixel| (pixel.ord - 256) / 16 == 5 } }
      expect(visible.to_f / thrust.length).to be >= 0.95
    end
  end

  it 'removes rocks only when an advancing shot actually intersects their wrapped collision radius' do
    [5, 8, 16].each do |size|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: 73)
      collisions = 0
      frames.each_cons(2) do |before, after|
        a = before[:state]
        b = after[:state]
        next unless a[:ship] && b[:ship]

        removed = a[:rocks].reject { |rock| b[:rocks].any? { |other| other[5] == rock[5] } }
        removed.each do |rock|
          expect(after[:event]).to eq(:hit)
          x, y, angle = b[:ship]
          candidates = a[:shots] + [[x, y, Math.cos(angle) * 0.36, Math.sin(angle) * 0.36]]
          expect(candidates.any? do |shot|
            dx = described_class.send(:mini_delta, from: shot[0] + shot[2], to: rock[0] + rock[2], span: size)
            dy = described_class.send(:mini_delta, from: shot[1] + shot[3], to: rock[1] + rock[3], span: size - 1)
            (dx * dx) + (dy * dy) <= rock[4]**2
          end).to be(true)
          collisions += 1
        end
      end
      expect(collisions).to be > 10
    end
  end

  it 'uses a faster presentation cadence and subcell, one-cell-high Pong paddles' do
    expect(described_class.mini_frame_seconds(name: :pong)).to eq(0.05)
    expect(described_class.mini_frame_seconds(name: :snake)).to eq(0.1)
    (5..16).each do |size|
      frames = described_class.send(:mini_replay, name: :pong, width: size, height: size, seed: 73)
      states = frames.filter_map { |frame| frame[:state] if frame[:state][:ball] }
      expect(states.map { |state| state[:paddle_height] }.uniq).to eq([1.0])
      frames.each_cons(2) do |a, b|
        next unless a[:state][:ball] && b[:state][:ball]

        expect(a[:state][:ball].zip(b[:state][:ball]).map { |x, y| (x - y).abs }).to all(be <= 0.51)
      end
      glyphs = (6...180).flat_map { |frame| described_class.mini_cells(name: :pong, width: size, height: size, frame: frame).flatten.map { |cell| cell[:glyph] } }
      expect(glyphs & %w[▘ ▝ ▖ ▗]).not_to be_empty
    end
  end

  it 'replays extended seeded gameplay instead of repeating every six seconds' do
    expect(described_class::MINI_FRAME_COUNT).to be >= 1800
    described_class.mini_names.each do |name|
      frames = Array.new(240) { |frame| described_class.mini_cells(name: name, frame: frame, seed: 73) }
      expect(frames.uniq.length).to be > 80
      expect(frames[0, 60]).not_to eq(frames[60, 60])
      expect(frames).to eq(Array.new(240) { |frame| described_class.mini_cells(name: name, frame: frame, seed: 73) })
      expect(frames).not_to eq(Array.new(240) { |frame| described_class.mini_cells(name: name, frame: frame, seed: 74) })
    end
  end
end

describe PWN::Banner do
  describe '.mini_cells' do
    it 'returns independent mutable cells and glyph strings even on clear frames' do
      described_class.mini_names.each do |name|
        [0, 26, 58].each do |frame|
          args = { name: name, frame: frame }
          original = described_class.mini_cells(**args)
          changed = described_class.mini_cells(**args)
          expect(changed.flatten.map(&:object_id).uniq.length).to eq(256)
          expect(changed.flatten.map { |cell| cell[:glyph].object_id }.uniq.length).to eq(256)
          changed.flatten.each do |cell|
            cell[:glyph].replace('!')
            cell[:foreground] = :red
          end
          expect(described_class.mini_cells(**args)).to eq(original)
        end
      end
    end

    it 'keeps every frame bounded, single-column, named-color, deterministic and side-effect free' do
      expect(Random).not_to receive(:rand)
      expect(Time).not_to receive(:now)
      expect(Process).not_to receive(:clock_gettime)
      expect(Thread).not_to receive(:new)
      expect(described_class).not_to receive(:sleep)
      expect do
        described_class.mini_names.each do |name|
          (5..16).each do |size|
            args = { name: name, width: size, height: size }
            frames = Array.new(60) { |frame| described_class.mini_cells(**args, frame: frame) }
            expect(frames.uniq.length).to be >= 4
            expect(frames.map(&:length)).to all(eq(size))
            expect(frames.flatten(1).map(&:length)).to all(eq(size))
            frames.flatten(2).each do |cell|
              expect(cell.keys).to contain_exactly(:glyph, :foreground, :background)
              expect(cell[:glyph]).to match(/\A[ PWN█▀▄▌▐░▘▝▖▗▞▛▚▜▙▟]\z/)
              expect(%i[black red green yellow blue magenta cyan white]).to include(cell[:foreground], cell[:background])
            end
            expect(described_class.mini_cells(**args, frame: described_class::MINI_FRAME_COUNT)).to eq(frames.first)
            expect(described_class.mini_cells(**args, frame: -1)).to eq(described_class.mini_cells(**args, frame: described_class::MINI_FRAME_COUNT - 1))
            expect(described_class.mini_cells(**args, name: name.to_s, frame: 23)).to eq(frames[23])
          end
        end
      end.to output('').to_stdout.and output('').to_stderr
      expect(described_class.mini_cells(width: 0)).to eq([])
      expect(described_class.mini_cells(height: -1)).to eq([])
      expect(described_class.mini_cells(name: :snake, width: 100, height: 100)).to eq(described_class.mini_cells(name: :snake))
      expect(described_class.mini_cells(width: 100, height: 100)).to eq(described_class.mini_cells(width: 64, height: 64))
      expect(described_class.mini_cells(width: '3', height: '2').map { |row| row.map { |cell| cell[:glyph] }.join }).to eq(['PWN', '   '])
      expect { described_class.mini_cells(name: :unknown) }.to raise_error(ArgumentError, /Unknown mini-banner/)
    end

    def replay(name, size, seed = 73)
      described_class.send(:mini_replay, name: name, width: size, height: size, seed: seed)
    end

    def logical_ink(frame, full: false)
      width = frame[:rows].first.length
      height = frame[:rows].length - 1
      height *= 2 if full
      Array.new(height) do |y|
        Array.new(width) do |x|
          px = full ? x * 2 : x + (width / 2)
          py = y + (full ? 0 : height / 2)
          pixel = frame[:rows][1 + (py / 2)][px / 2]
          mask = pixel == ' ' ? 0 : (pixel.ord - 256) % 16
          mask[(py % 2 * 2) + (px % 2)] == 1 ? '*' : ' '
        end.join
      end
    end

    it 'rejects unreachable placements rather than ending a game on a blocked rotation' do
      board = ['     ', 'r    ', 'r    ', 'rr   ']
      shape = described_class::MINI_SHAPES.first
      landing = described_class.send(:mini_landing, board: board, shape: shape, rng: Random.new(73))
      rotations = described_class.send(:mini_rotations, shape: shape)
      expect(landing).not_to be_nil
      rotations.take(landing[:rotation] + 1).each do |piece|
        expect(described_class.send(:mini_fits?, board: board, shape: piece, x: 0, y: 0)).to be(true)
      end
      (0..landing[:x]).each do |x|
        expect(described_class.send(:mini_fits?, board: board, shape: landing[:shape], x: x, y: 0)).to be(true)
      end
    end

    it 'stacks all seven four-cell tetrominoes with legal gravity, rotations and line collapse' do
      (5..16).each do |size|
        frames = replay(:falling_blocks, size)
        active = frames.select { |frame| frame[:state][:active] }
        expect(active.map { |frame| frame[:state][:type] }.uniq.length).to eq(7)
        expect(frames.map { |frame| frame[:event] }).to include(:lock, :clear, :collapse)
        active.each do |frame|
          points, stack = frame[:state].values_at(:active, :stack)
          expect(points.uniq.length).to eq(4)
          points.each do |x, y|
            expect(x).to be_between(0, size - 1)
            expect(y).to be_between(0, ((size - 1) * 2) - 1)
            expect(stack[y][x]).to eq(' ')
          end
          expected = stack.map { |row| row.gsub(/[^ ]/, '*') }
          points.each { |x, y| expected[y][x] = '*' }
          expect(logical_ink(frame, full: true)).to eq(expected)
        end
        frames.each_cons(2) do |before, after|
          a = before[:state][:active]
          b = after[:state][:active]
          if a && b
            expect(before[:state][:stack]).to eq(after[:state][:stack])
            expect(b.map(&:last).min - a.map(&:last).min).to be_between(0, 1)
            expect((b.map(&:first).min - a.map(&:first).min).abs).to be <= 1
          elsif a && after[:event] == :lock
            stack = before[:state][:stack]
            expect(a.any? { |x, y| y == ((size - 1) * 2) - 1 || stack[y + 1][x] != ' ' }).to be(true)
            expect(after[:rows]).to eq(before[:rows])
          elsif before[:event] == :clear && after[:event] == :collapse
            lines = before[:state][:lines]
            expect(lines.map { |y| logical_ink(before, full: true)[y] }).to all(eq('*' * size))
            survivors = logical_ink(before, full: true).each_with_index.filter_map { |row, y| row unless lines.include?(y) }
            expect(logical_ink(after, full: true)).to eq(Array.new(lines.length, ' ' * size) + survivors)
          end
        end
      end
    end

    it 'moves a contiguous non-overlapping snake toward real food and grows only on pickup' do
      (5..16).each do |size|
        frames = replay(:snake, size)
        states = frames.filter_map { |frame| frame[:state] if frame[:state][:body] }
        expect(states.map { |state| state[:body].length }.max).to be > 6
        states.each do |state|
          body, food = state.values_at(:body, :food)
          expect(body.uniq.length).to eq(body.length)
          body.each do |x, y|
            expect(x).to be_between(0, size - 1)
            expect(y).to be_between(0, size - 2)
          end
          body.each_cons(2) { |a, b| expect(a.zip(b).sum { |x, y| (x - y).abs }).to eq(1) }
          expect(body).not_to include(food) if food
        end
        frames.each do |frame|
          body, food = frame[:state].values_at(:body, :food)
          next unless body

          expected = Array.new(size - 1) { ' ' * size }
          (body + [food].compact).each { |x, y| expected[y][x] = '*' }
          expect(logical_ink(frame)).to eq(expected)
        end
        frames.each_cons(2) do |before, after|
          a = before[:state]
          b = after[:state]
          next unless a[:body] && b[:body] && a != b

          expect(a[:body].first.zip(b[:body].first).sum { |x, y| (x - y).abs }).to eq(1)
          if b[:body].first == a[:food]
            expect(b[:body].drop(1)).to eq(a[:body])
          else
            expect(b[:body].drop(1)).to eq(a[:body].take(a[:body].length - 1))
            expect(b[:food]).to eq(a[:food])
          end
        end
      end
    end

    it 'plays varied Pong rallies with legal reflections, paddle tracking, misses and scores' do
      (5..16).each do |size|
        frames = replay(:pong, size)
        expect(frames.map { |frame| frame[:event] }).to include(:bounce, :score, :serve)
        expect(frames.filter_map { |frame| frame[:state][:rally] }.max).to be >= 2
        expect(frames.filter_map { |frame| frame[:state][:rally] }.max).to be >= 5 if size == 16
        frames.each_cons(2) do |before, after|
          a = before[:state]
          b = after[:state]
          next unless a[:paddles] && b[:paddles]

          expect(a[:paddles].zip(b[:paddles]).map { |x, y| (x.round - y.round).abs }).to all(be <= 1)
          if a[:ball] && b[:ball]
            expect(a[:ball].zip(b[:ball]).map { |x, y| (x.round - y.round).abs }).to all(be <= 1)
            expect(b[:ball][0]).to be_between(0, size - 1)
            expect(b[:ball][1]).to be_between(0, size - 2)
            if after[:event] == :bounce
              side = b[:ball][0] < (size - 1) / 2.0 ? 0 : 1
              expect(b[:ball][1] - b[:paddles][side]).to be_between(-0.25, 0.75)
              expect(a[:ball][0]).to be_between(1, size - 2)
            end
          elsif a[:ball] && after[:event] == :score
            expect(a[:ball][0] < 1 || a[:ball][0] > size - 2).to be(true)
            expect(b[:scores].sum - a[:scores].sum).to eq(1)
          elsif b[:ball]
            expect(after[:event]).to eq(:serve)
          end
        end
      end
    end

    it 'returns deterministic named-color block cells without changing the ASCII API' do
      rows = described_class.mini_cells(name: :falling_blocks, width: 5, height: 5)
      expect(rows.length).to eq(5)
      expect(rows.map(&:length)).to eq([5] * 5)
      expect(rows.first.map { |cell| cell[:glyph] }.join).to eq(' PWN ')
      expect(rows[1][1]).to eq(glyph: ' ', foreground: :blue, background: :black)
      expect(described_class.mini_cells(name: :falling_blocks, width: 5, height: 5, frame: described_class::MINI_FRAME_COUNT)).to eq(rows)
      expect(described_class.mini_frame(width: 5, height: 5)[1]).to eq(' ### ')
    end

    it 'bounds immutable replay caching and survives eviction, arbitrary seek and caller mutation' do
      first = replay(:snake, 8)
      expect(first.length).to eq(described_class::MINI_FRAME_COUNT)
      expect(first).to be_frozen
      expect { first[20][:rows][1].replace('bad') }.to raise_error(FrozenError)
      expect { first[20][:state][:body][0][0] = 99 }.to raise_error(FrozenError)
      expect(replay(:snake, 8)).to equal(first)
      9.times { |seed| replay(:pong, 5, seed) }
      expect(described_class.instance_variable_get(:@mini_replays).length).to eq(described_class::MINI_CACHE_LIMIT)
      expect(replay(:snake, 8)).to eq(first)
      [1799, -1, 921, 600, 6, 1800, -1800].each do |frame|
        cells = described_class.mini_cells(name: :snake, width: 8, height: 8, frame: frame)
        expect(cells.map { |row| row.map { |cell| cell[:glyph] }.join }).to eq(
          first[frame % described_class::MINI_FRAME_COUNT][:rows].map { |row| row.chars.map { |pixel| described_class::MINI_PIXELS.fetch(pixel).first }.join }
        )
      end
    end

    it 'has a visible reset and blank-to-blank seam rather than teleporting at replay wrap' do
      described_class.mini_names.each do |name|
        [5, 8, 16].each do |size|
          frames = replay(name, size)
          expect(frames.length).to eq(described_class::MINI_FRAME_COUNT)
          expect(frames.last[:rows]).to eq(frames.first[:rows])
          expect(frames[-size - 6][:event]).to eq(:reset)
          frames.last(size).each_cons(2) do |before, after|
            expect(before[:rows].zip(after[:rows]).count { |a, b| a != b }).to be <= 1
          end
        end
      end
    end
  end
end

describe PWN::Banner do
  describe '.mini_frame' do
    it 'offers retro games with deterministic cycles and branding at every square size' do
      expect(described_class.mini_names).to eq(%i[falling_blocks snake pong asteroids])
      described_class.mini_names.each do |name|
        (5..16).each do |size|
          args = { name: name, width: size, height: size }
          frames = Array.new(described_class::MINI_FRAME_COUNT) { |frame| described_class.mini_frame(**args, frame: frame) }
          expect(frames.uniq.length).to be >= 4
          expect(frames.flatten).to all(match(/\A[ -~]{#{size}}\z/))
          expect(frames.map(&:length)).to all(eq(size))
          expect(frames.map(&:first)).to all(include('PWN'))
          expect(described_class.mini_frame(**args, frame: described_class::MINI_FRAME_COUNT)).to eq(frames.first)
          expect(described_class.mini_frame(**args, name: name.to_s, frame: -1)).to eq(frames.last)
          expect(described_class.mini_frame(**args, frame: 3)).to eq(frames[3])
        end
      end
    end

    it 'returns a compact printable ASCII wordmark without terminal side effects' do
      lines = nil
      expect { lines = described_class.mini_frame(frame: 0) }.not_to output.to_stdout
      expect(lines.length).to eq(16)
      expect(lines).to all(match(/\A[ -~]{16}\z/))
      expect(lines.first).to include('PWN')
    end

    it 'clips safely for tiny panes and caps oversized requests at native dimensions' do
      described_class.mini_names.each do |name|
        [1, 3, 5, 8, 16].product([1, 3, 5, 8, 16]).each do |width, height|
          rows = described_class.mini_frame(name: name, width: width, height: height)
          expect(rows.length).to eq(height)
          expect(rows.map(&:length)).to all(eq(width))
        end
      end
      expect(described_class.mini_frame(width: 0)).to eq([])
      expect(described_class.mini_frame(height: -1)).to eq([])
      expect(described_class.mini_frame(width: -1)).to eq([])
      expect(described_class.mini_frame(width: 10**20, height: 10**20)).to eq(described_class.mini_frame)
      expect(described_class.mini_frame(name: nil, frame: nil, width: nil, height: nil)).to eq(described_class.mini_frame)
      expect(described_class.mini_frame(width: '3', height: '2').map(&:length)).to eq([3, 3])
    end

    it 'returns independent rows and name lists without retaining caller mutations' do
      original = described_class.mini_frame
      changed = described_class.mini_frame
      changed.first.replace('changed')
      changed.clear
      described_class.mini_names.clear
      expect(described_class.mini_frame).to eq(original)
      expect(described_class.mini_names.length).to eq(4)
    end

    it 'keeps recognizable pieces, bodies and paddles in the smallest complete canvas' do
      expect(described_class.mini_frame(name: :falling_blocks, width: 5, height: 5)).to eq(
        [' PWN ', ' ### ', '  #  ', '#   #', '## ##']
      )
      expect(described_class.mini_frame(name: :snake, width: 5, height: 5)).to eq(
        [' PWN ', '@    ', 'o *  ', 'o    ', 'oo   ']
      )
      expect(described_class.mini_frame(name: :pong, width: 5, height: 5)).to eq(
        [' PWN ', '|o: |', '|   |', '  :  ', '     ']
      )
    end

    it 'lands tetrominoes before flashing and clearing the completed rows' do
      [5, 8, 16].each do |size|
        [0, 30].each do |start|
          args = { name: :falling_blocks, width: size, height: size }
          expect(described_class.mini_frame(**args, frame: start + 24).last(2)).to eq(['#' * size] * 2)
          expect(described_class.mini_frame(**args, frame: start + 26).last(2)).to eq(['=' * size] * 2)
          expect(described_class.mini_frame(**args, frame: start + 29).last(2)).to eq([' ' * size] * 2)
        end
      end
    end

    it 'moves snake and ball at most one cell per axis including the loop seam' do
      { snake: '@', pong: 'o' }.each do |name, glyph|
        (5..16).each do |size|
          positions = Array.new(described_class::MINI_FRAME_COUNT + 1) do |frame|
            rows = described_class.mini_frame(name: name, frame: frame, width: size, height: size)
            y = rows.index { |row| row.include?(glyph) }
            [rows[y].index(glyph), y]
          end
          positions.each_cons(2) do |before, after|
            expect((before[0] - after[0]).abs).to be <= 1
            expect((before[1] - after[1]).abs).to be <= 1
          end
        end
      end
    end

    it 'never aliases mutable rows even during the line-clear animation' do
      described_class.mini_names.each do |name|
        described_class::MINI_FRAME_COUNT.times do |frame|
          rows = described_class.mini_frame(name: name, frame: frame)
          expect(rows.map(&:object_id).uniq.length).to eq(rows.length)
        end
      end
    end

    it 'never samples randomness, reads the clock, starts threads, sleeps, or prints' do
      expect(Random).not_to receive(:rand)
      expect(Time).not_to receive(:now)
      expect(Process).not_to receive(:clock_gettime)
      expect(Thread).not_to receive(:new)
      expect(described_class).not_to receive(:sleep)
      expect do
        described_class.mini_names.each { |name| described_class.mini_frame(name: name, frame: 5) }
      end.to output('').to_stdout.and output('').to_stderr
    end

    it 'rejects unknown artwork rather than silently randomizing it' do
      expect { described_class.mini_frame(name: :missing) }.to raise_error(ArgumentError, /Unknown mini-banner/)
    end

    it 'preserves the original static banner dispatch' do
      modules = %i[Anon Bubble Cheshire CodeCave DontPanic ForkBomb FSociety JmpEsp Matrix Ninja OffTheAir Pirate Radare2 Radare2AI WhiteRabbit]
      modules.each_with_index do |name, index|
        expect(described_class.const_get(name)).to receive(:get).and_return(name.to_s)
        expect(described_class.get(index: index + 1)).to eq(name.to_s)
      end
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::Banner
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Banner
    expect(help_response).to respond_to :help
  end
end
