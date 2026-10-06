# frozen_string_literal: true

require 'spec_helper'

describe PWN::Banner do
  it 'keeps compact ghost hints in one cell rather than reserving multi-cell actor tiles' do
    %w[R M C F].each do |pixel|
      glyph, = described_class::MINI_PIXELS.fetch(pixel)
      expect(glyph.length).to eq(1)
      expect(glyph).to eq('⣻')
    end
  end

  it 'advances Galaga waves after actual shot hits and detects both enemy and hostile-shot collisions' do
    opts = { width: 8, height: 8, rng: Random.new(3) }
    state = described_class.send(:mini_galaga_round, opts)
    state[:started] = true
    state[:enemies] = [{ x: 2.0, y: 1.0, home: [2, 1], diving: false, phase: 0 }]
    state[:shots] = [[2.0, 1.7]]
    expect(described_class.send(:mini_galaga_move, opts.merge(state: state))).to eq(:wave_complete)
    expect(state[:score]).to eq(50)
    expect(state[:enemies]).to be_empty
    state[:hostile] = [[state[:ship][0], state[:ship][1] - 0.3, 0]]
    expect(described_class.send(:mini_galaga_move, opts.merge(state: state))).to eq(:game_over)
    state[:hostile].clear
    state[:enemies] = [{ x: state[:ship][0], y: state[:ship][1] - 0.1, home: [2, 1], diving: true, phase: 0 }]
    expect(described_class.send(:mini_galaga_move, opts.merge(state: state))).to eq(:game_over)
    frames = described_class.send(:mini_replay, name: :galaga, width: 8, height: 9, seed: 3)
    expect(frames.map { |frame| frame[:event] }).to include(:wave_complete)
    expect(frames.any? { |frame| frame[:state][:level].to_i > 1 }).to be true
  end

  it 'progresses Frogger after all goals and rejects occupied goals and log-edge falls' do
    opts = { width: 8, height: 8, rng: Random.new(3) }
    state = described_class.send(:mini_frogger_round, opts)
    state[:started] = true
    state[:filled] = state[:goals].take(2)
    state[:frog] = [state[:goals].last.to_f, 1]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: [:up]))).to eq(:level_complete)
    state[:frog] = [state[:goals].last.to_f, 1]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: [:up]))).to eq(:game_over)
    water = state[:lanes].find { |lane| lane[:water] }
    water[:offset] = 6
    water[:speed] = 0.2
    state[:frog] = [7.0, water[:y]]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: []))).to eq(:game_over)
    frames = described_class.send(:mini_replay, name: :frogger, width: 5, height: 6, seed: 3)
    expect(frames.map { |frame| frame[:event] }).to include(:level_complete)
    expect(frames.any? { |frame| frame[:state][:level].to_i > 1 }).to be true
  end

  it 'recovers both new games to input-ready play and ignores wreck controls' do
    %i[galaga frogger].each do |name|
      game = described_class::MiniGame.new(name: name, width: 5, height: 5, seed: 3)
      game.step
      game.key(:up)
      frames = []
      600.times do
        frame = game.step
        frames << frame
        break if frame[:event] == :game_over
      end
      expect(frames.last[:event]).to eq(:game_over)
      8.times do
        game.key(:right)
        game.key(' ')
        game.step
      end
      ready = game.step
      expect(ready[:event]).to eq(:ready)
      5.times { expect(game.step).to eq(ready) }
      game.key(:left)
      expect(game.step[:event]).to eq(:play)
    end
  end

  it 'paints distinct directional mouths and compact ghosts without reducing maze dimensions' do
    opts = { width: 18, height: 12 }
    game = described_class::MiniGame.new(name: :pacman, **opts)
    state = Marshal.load(Marshal.dump(game.step[:state]))
    expect(state[:maze].first.length).to eq(18)
    expect(state[:maze].length).to eq(12)
    expect(state[:ghosts].map { |ghost| ghost[:color] }).to eq(%w[R M C])
    state[:ghosts].clear
    state[:pacman] = [2, 2]
    rows = %i[right down left up].map do |direction|
      state[:direction] = direction
      frames = []
      described_class.send(:mini_pacman_snapshot, frames: frames, state: state)
      expect(game.cells(frames.first).map(&:length)).to all(eq(18))
      frames.first[:rows]
    end
    expect(rows.uniq.length).to eq(4)
    state[:tick] = 2
    closed = []
    described_class.send(:mini_pacman_snapshot, frames: closed, state: state)
    expect(rows).not_to include(closed.first[:rows])
    state[:ghosts] = [{ position: [3, 2], color: 'R' }]
    ghosts = []
    described_class.send(:mini_pacman_snapshot, frames: ghosts, state: state)
    cells = game.cells(ghosts.first)
    expect(cells.flatten.count { |cell| cell[:foreground] == :red }).to eq(1)
  end

  it 'plays Frogger with immediate hops, traffic, moving logs, water deaths and goals' do
    game = described_class::MiniGame.new(name: :frogger, width: 8, height: 8, seed: 3)
    frame = game.step
    10.times { expect(game.step).to eq(frame) }
    game.key(:left)
    expect(game.step[:state][:frog][0]).to eq(frame[:state][:frog][0] - 1)
    opts = { width: 8, height: 8, rng: Random.new(3) }
    state = described_class.send(:mini_frogger_round, opts)
    water = state[:lanes].find { |lane| lane[:water] }
    water[:offset] = 0
    state[:frog] = [1.0, water[:y]]
    state[:started] = true
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: []))).to eq(:play)
    expect(state[:frog][0]).to be_within(0.001).of(1.0 + water[:speed])
    state[:frog] = [water[:length] + water[:offset] + 0.5, water[:y]]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: []))).to eq(:game_over)
    road = state[:lanes].find { |lane| !lane[:water] }
    state[:frog] = [road[:offset] + 0.5, road[:y]]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: []))).to eq(:game_over)
    state[:frog] = [state[:goals].first.to_f, 1]
    expect(described_class.send(:mini_frogger_move, opts.merge(state: state, keys: [:up]))).to eq(:goal)
    expect(state[:filled]).to eq([state[:goals].first])
    expect(state[:frog][1]).to eq(7)
  end

  it 'plays Galaga with input-ready launch, shots, formation enemies, dives and hostile fire' do
    game = described_class::MiniGame.new(name: :galaga, width: 12, height: 12, seed: 7)
    ready = game.step
    5.times { expect(game.step).to eq(ready) }
    expect(ready[:state][:enemies].length).to be > 4
    game.key(:left)
    moved = game.step
    expect(moved[:state][:ship][0]).to be < ready[:state][:ship][0]
    game.key(' ')
    expect(game.step[:state][:shots]).not_to be_empty
    frames = described_class.send(:mini_replay, name: :galaga, width: 12, height: 13, seed: 7)
    expect(frames.any? { |frame| frame[:state][:enemies]&.any? { |enemy| enemy[:diving] } }).to be true
    expect(frames.any? { |frame| frame[:state][:hostile]&.any? }).to be true
    expect(frames.map { |frame| frame[:event] }).to include(:hit, :game_over)
  end

  it 'randomizes real maze walls while retaining connected pellets and power across seeds and rounds' do
    [5, 6, 8, 11, 16, 24].each do |size|
      mazes = 12.times.map do |seed|
        state = described_class.send(:mini_pacman_round, width: size, height: size, rng: Random.new(seed))
        reachable = [state[:pacman]]
        reachable.each do |point|
          described_class.send(:mini_pacman_neighbors, point: point, maze: state[:maze]).each_value do |neighbor|
            reachable << neighbor unless reachable.include?(neighbor)
          end
        end
        expect((state[:pellets] + state[:power]) - reachable).to be_empty
        state[:maze]
      end
      expect(mazes.uniq.length).to be >= (size == 5 ? 2 : 4)
      rng = Random.new(91)
      rounds = Array.new(8) { described_class.send(:mini_pacman_round, width: size, height: size, rng: rng)[:maze] }
      expect(rounds.uniq.length).to be > 1
    end
  end

  it 'selects Pac-Man instead of Pong and renders a connected pellet maze at every supported size' do
    expect(described_class.mini_names).to eq(%i[falling_blocks snake pacman asteroids galaga frogger])
    [5, 6, 8, 11, 16].each do |size|
      game = described_class::MiniGame.new(name: :pacman, width: size, height: size)
      frame = game.step
      state = frame[:state]
      maze = state[:maze]
      open = (0...maze.length).flat_map { |y| (0...maze.first.length).filter_map { |x| [x, y] unless maze[y][x] == '#' } }
      reached = [state[:pacman]]
      reached.each do |x, y|
        [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]].each do |point|
          reached << point if open.include?(point) && !reached.include?(point)
        end
      end
      expect(reached.sort).to eq(open.sort)
      expect(state[:pellets]).not_to be_empty
      expect(state[:power].length).to eq(4)
      expect(frame[:event]).to eq(:ready)
      expect(game.cells(frame).length).to eq(size)
      expect(game.cells(frame).map(&:length)).to all(eq(size))
      10.times { expect(game.step).to eq(frame) }
    end
  end

  it 'resolves Pac-Man power pellets before ghost contact and respawns eaten ghosts' do
    state = described_class.send(:mini_pacman_round, width: 7, height: 7)
    state[:pacman] = [2, 1]
    state[:ghosts][0][:position] = [1, 1]
    expect(described_class.send(:mini_pacman_move, state: state, keys: [:left], rng: Random.new(3))).to eq(:ghost_eaten)
    expect(state[:score]).to eq(250)
    expect(state[:frightened]).to be_positive
    expect(state[:power]).not_to include([1, 1])
    expect(state[:ghosts][0][:position]).to eq(state[:ghosts][0][:home])
    expect(state[:ghosts][0][:delay]).to be_positive
  end

  it 'does not eat a returning ghost twice or kill Pac-Man while it is recovering at home' do
    state = described_class.send(:mini_pacman_round, width: 7, height: 7)
    state[:pacman] = state[:ghosts][0][:home].dup
    state[:frightened] = 5
    expect(described_class.send(:mini_pacman_contact, state: state)).to eq(:ghost_eaten)
    expect(described_class.send(:mini_pacman_contact, state: state)).to be_nil
    state[:frightened] = 0
    expect(described_class.send(:mini_pacman_contact, state: state)).to be_nil
    expect(state[:score]).to eq(200)
  end

  it 'detects Pac-Man collisions, expires fright, completes levels and recovers to arrow-ready play' do
    state = described_class.send(:mini_pacman_round, width: 7, height: 7)
    state[:ghosts][0][:position] = [2, 5]
    state[:frightened] = 1
    expect(described_class.send(:mini_pacman_move, state: state, keys: [:right], rng: Random.new(3))).to eq(:game_over)
    state[:ghosts].clear
    state[:pellets] = [[3, 5]]
    state[:power].clear
    state[:tick] = 0
    expect(described_class.send(:mini_pacman_move, state: state, keys: [:right], rng: Random.new(3))).to eq(:level_complete)

    game = described_class::MiniGame.new(name: :pacman, width: 5, height: 5)
    game.step
    game.key(:right)
    frames = Array.new(500) { game.step }
    death = frames.index { |frame| frame[:event] == :game_over }
    expect(death).not_to be_nil
    x, y = frames[death][:state][:pacman]
    expect(game.cells(frames[death])[y][x]).to include(glyph: '█', foreground: :white)
    expect(frames.drop(death + 6).map { |frame| frame[:event] }).to all(eq(:ready))
    game.key(:up)
    expect(game.step[:event]).to eq(:play)
  end

  it 'runs reproducible Pac-Man demos with moving ghosts, eating, recovery and complete bounded frames' do
    [5, 8, 16].each do |size|
      frames = described_class.send(:mini_replay, name: :pacman, width: size, height: size + 1, seed: 42)
      expect(frames.length).to eq(1800)
      expect(frames.map { |frame| frame[:event] }).to include(:play, :power)
      expect(frames.map { |frame| frame[:event] }).to include(:level_complete) if size == 5
      expect(frames.filter_map { |frame| frame[:state][:pacman] }.uniq.length).to be > 5
      expect(frames.filter_map { |frame| frame[:state][:ghosts]&.first&.dig(:position) }.uniq.length).to be > 2
      expect(frames.map { |frame| frame[:rows].length }).to all(eq(size + 1))
      expect(frames.flat_map { |frame| frame[:rows].map(&:length) }).to all(eq(size))
      described_class.instance_variable_set(:@mini_replays, {})
      expect(described_class.send(:mini_replay, name: :pacman, width: size, height: size + 1, seed: 42)).to eq(frames)
    end
  end

  it 'reclaims the wordmark row for unbranded games and leaves tiny panes blank' do
    described_class.mini_names.product([1, 3, 5, 8, 16]).each do |name, size|
      [0, 6, 100, 1799].each do |frame|
        args = { name: name, width: size, height: size, frame: frame, branding: false }
        cells = described_class.mini_cells(**args)
        ascii = described_class.mini_frame(**args)
        expect(cells.length).to eq(size)
        expect(cells.map(&:length)).to all(eq(size))
        expect(cells.flatten.map { |cell| cell[:glyph] }.join).not_to match(/[PWN]/)
        expect(ascii.length).to eq(size)
        expect(ascii.map(&:length)).to all(eq(size))
        expect(ascii.join).not_to match(/[PWN]/)
        next if size < 5

        replay = described_class.send(:mini_replay, name: name, width: size, height: size + 1, seed: 73)
        expected = replay[frame][:rows].drop(1).map do |row|
          row.chars.map { |pixel| described_class::MINI_PIXELS.fetch(pixel).first }.join
        end
        expect(cells.map { |row| row.map { |cell| cell[:glyph] }.join }).to eq(expected)
      end
    end
  end
end

describe PWN::Banner::MiniGame do
  it 'paints Galaga as a filled symmetric upward triangle without changing ship physics' do
    [8, 12, 24].each do |size|
      game = described_class.new(name: :galaga, width: size, height: size)
      frame = game.step
      expect(frame[:state][:ship]).to eq([size / 2.0, size - 1.0])
      dots = []
      game.cells(frame).each_with_index do |row, y|
        row.each_with_index do |cell, x|
          next unless cell[:foreground] == :cyan

          mask = cell[:glyph].ord - 0x2800
          [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2], [0, 3], [1, 3]].each_with_index do |(dx, dy), bit|
            dots << [(x * 2) + dx, (y * 4) + dy] if mask[bit] == 1
          end
        end
      end
      rows = dots.group_by(&:last).sort.map { |_, points| points.map(&:first).sort }
      expect(rows.map(&:length)).to eq([1, 3, 3, 5, 5])
      rows.each { |xs| expect(xs).to eq((xs.first..xs.last).to_a) }
      expect(rows.map { |xs| xs.first + xs.last }.uniq.length).to eq(1)
      game.key(:left)
      expect(game.step[:state][:ship]).to eq([(size / 2.0) - 0.75, size - 1.0])
    end
  end

  it 'retains inner walls and branching corridors with single-cell actors in delivered console panes' do
    # The console starts at an eight-cell interior at both 100x26 and 120x36.
    # Settings can grow that pane; include odd, even and large interiors.
    [8, 9, 12, 18, 24].each do |size|
      layouts = 12.times.map do |seed|
        game = described_class.new(name: :pacman, width: size, height: size, seed: seed)
        frame = game.step
        maze = frame[:state][:maze]
        expect(maze.length).to eq(size)
        expect(maze.map(&:length)).to all(eq(size))
        inner = maze[2...-2].map { |row| row[2...-2] }.join
        expect(inner.count('#')).to be >= 4
        expect(inner.count('#').fdiv(inner.length)).to be_between(0.2, 0.8)
        expect(inner.count(' ')).to be >= 4
        reached = [frame[:state][:pacman]]
        reached.each do |point|
          PWN::Banner.send(:mini_pacman_neighbors, point: point, maze: maze).each_value do |neighbor|
            reached << neighbor unless reached.include?(neighbor)
          end
        end
        expect(reached.length).to eq(maze.join.count(' '))
        expect(frame[:rows].join.count('><^vO')).to eq(1)
        expect(frame[:rows].join.count('RMCF')).to eq(frame[:state][:ghosts].length)
        expect(frame[:rows][1]).to eq('#' * size)
        expect(frame[:rows].last).to eq('#' * size)
        game.key(:right)
        expect(game.step[:state][:pacman]).to eq([2, size - 2])
        maze
      end
      expect(layouts.uniq.length).to be >= 8
    end
  end

  it 'uses the entire Pac-Man pane beyond sixteen cells without shrinking or padding the maze' do
    [17, 24, 64].each do |size|
      game = described_class.new(name: :pacman, width: size, height: size)
      frame = game.step
      expect(game.cells(frame).length).to eq(size)
      expect(game.cells(frame).map(&:length)).to all(eq(size))
      expect(frame[:state][:maze].last).to eq('#' * size)
      game.key(:up)
      expect(game.step[:state][:pacman]).to eq([1, size - 3])
    end
  end

  it 'starts Pac-Man on arrows, eats pellets, buffers a blocked turn and stops at walls' do
    game = described_class.new(name: :pacman, width: 7, height: 7, seed: 9)
    expect(game.step[:state][:pacman]).to eq([1, 5])
    game.key(:right)
    moved = game.step
    expect(moved[:state][:pacman]).to eq([2, 5])
    expect(moved[:state][:score]).to eq(10)
    game.key(:up)
    2.times { game.step }
    expect(game.step[:state][:pacman]).to eq([3, 5])
    2.times { game.step }
    expect(game.step[:state][:pacman]).to eq([3, 4])
    game.key(:left)
    2.times { game.step }
    expect(game.step[:state][:pacman]).to eq([3, 3])
  end

  it 'renders bounded, unbranded colored frames without accumulating a replay' do
    PWN::Banner.mini_names.product([5, 8, 16]).each do |name, size|
      game = described_class.new(name: name, width: size, height: size)
      40.times do
        frame = game.step
        cells = game.cells(frame)
        expect(cells.length).to eq(size)
        expect(cells.map(&:length)).to all(eq(size))
        expect(cells.flatten.map { |cell| cell[:glyph] }.join).not_to match(/[PWN]/)
        expect(cells.flatten).to all(include(:foreground, :background))
      end
      expect(game.length).to eq(0)
    end
  end

  it 'lets the player move only the left Pong paddle while the ball and opponent keep playing' do
    game = PWN::Banner::MiniGame.new(name: :pong, width: 8, height: 8, seed: 73)
    first = game.step
    game.key(:up)
    moved = game.step
    expect(moved[:state][:paddles][0]).to be < first[:state][:paddles][0]
    expect(moved[:state][:ball]).not_to eq(first[:state][:ball])
    game.key(:down)
    expect(game.step[:state][:paddles][0]).to eq(first[:state][:paddles][0])
    game.key(:left)
    expect(game.step[:state][:paddles][0]).to eq(first[:state][:paddles][0])
    100.times do
      game.key(:up)
      game.step
    end
    expect(game.step[:state][:paddles][0]).to eq(0)
  end

  it 'steers Snake with arrows without reversing into its neck or changing direction twice per tick' do
    game = PWN::Banner::MiniGame.new(name: :snake, width: 16, height: 16, seed: 73)
    first = game.step[:state]
    game.key(:left)
    moved = game.step[:state]
    expect(moved[:body].first).to eq([first[:body][0][0] + 1, first[:body][0][1]])
    turn = moved[:body][0][1].positive? ? :up : :down
    game.key(turn)
    game.key(:left)
    turned = game.step[:state]
    expect(turned[:body].first).to eq([moved[:body][0][0], moved[:body][0][1] + (turn == :up ? -1 : 1)])
    game.key(:left)
    expect(game.step[:state][:body].first[0]).to eq(turned[:body][0][0] - 1)
  end

  it 'keeps Snake stopped after collision until a new arrow starts the next round' do
    game = described_class.new(name: :snake, width: 5, height: 5, seed: 73)
    expect(game.step[:event]).to eq(:ready)
    game.key(:right)
    7.times { expect(game.step[:event]).to eq(:play) }
    expect(game.step[:event]).to eq(:game_over)
    ready = game.step
    expect(ready[:event]).to eq(:ready)
    20.times { expect(game.step).to eq(ready) }
    game.key(:up)
    expect(game.step[:state][:body].first).to eq([2, 4])
  end

  it 'packs playable Snake over the full width and bottom with quarter-cell pixels' do
    [5, 8, 16].each do |size|
      board = Array.new(size * 2) { ' ' * (size * 2) }
      board[0][0] = 'g'
      board[-1][-1] = 'y'
      game = described_class.new(name: :snake, width: size, height: size)
      cells = game.cells(rows: ['label'] + board)
      expect(cells.first.first).to include(glyph: '▘', foreground: :green)
      expect(cells.last.last).to include(glyph: '▗', foreground: :yellow)
    end
  end

  it 'moves Tetris sideways, rotates with space and soft drops one row with down' do
    game = PWN::Banner::MiniGame.new(name: :falling_blocks, width: 8, height: 8, seed: 73)
    first = game.step[:state]
    game.key(:left)
    left = game.step[:state]
    expect(left[:active]).to eq(first[:active].map { |x, y| [x - 1, y] })
    game.key(:right)
    expect(game.step[:state][:active]).to eq(first[:active])
    game.key(' ')
    rotated = game.step[:state]
    expect(rotated[:active]).not_to eq(first[:active])
    expect(rotated[:active].map(&:last).min).to eq(0)
    game.key(:down)
    dropped = game.step[:state]
    expect(dropped[:active]).to eq(rotated[:active].map { |x, y| [x, y + 1] })
    expect(dropped[:stack]).to eq(first[:stack])
    events = 150.times.map do
      game.key(:down)
      game.step[:event]
    end
    expect(events).to include(:lock)
  end

  it 'explodes on a real ship impact, ignores wreck controls, then recovers with brief protection' do
    rng = instance_double(Random)
    allow(Random).to receive(:new).with(73).and_return(rng)
    allow(rng).to receive(:rand).and_return(0.0, 0.82, 0.5, 0.0, 0.5)
    game = described_class.new(name: :asteroids, width: 5, height: 5, seed: 73)
    frames = Array.new(20) { game.step }
    crash = frames.find { |frame| frame[:event] == :crash }
    expect(crash).not_to be_nil
    ship = crash[:state][:ship]
    expect(crash[:state][:rocks].any? do |rock|
      dx = PWN::Banner.send(:mini_delta, from: ship[0], to: rock[0], span: 5)
      dy = PWN::Banner.send(:mini_delta, from: ship[1], to: rock[1], span: 5)
      (dx * dx) + (dy * dy) <= (rock[4] + 0.55)**2
    end).to be(true)
    wrecks = frames.select { |frame| frame[:state][:explosion].to_i.positive? }
    expect(wrecks.length).to be >= 8
    expect(wrecks.map { |frame| frame[:rows] }.uniq.length).to be >= 4
    wrecks.each do |frame|
      expect(game.cells(frame).flatten.any? { |cell| cell[:foreground] == :cyan && cell[:glyph] != ' ' }).to be(false)
      expect(game.cells(frame).flatten.any? { |cell| %i[red yellow white].include?(cell[:foreground]) && cell[:glyph] != ' ' }).to be(true)
    end
    game.key(:up)
    game.key(' ')
    frozen = game.step
    expect(frozen[:state][:ship]).to eq(ship)
    expect(frozen[:state][:shots]).to be_empty
    recovery = Array.new(15) { game.step }.find { |frame| frame[:event] == :recover }
    expect(recovery).not_to be_nil
    expect(recovery[:state][:invulnerable]).to be_positive
    game.key(:up)
    expect(game.step[:state][:ship]).not_to eq(ship)
  end

  it 'turns and thrusts Asteroids only on arrows and fires only on space' do
    game = PWN::Banner::MiniGame.new(name: :asteroids, width: 16, height: 16, seed: 73)
    first = game.step[:state]
    idle = game.step[:state]
    expect(idle[:ship]).to eq(first[:ship])
    expect(idle[:shots]).to be_empty
    game.key(:left)
    left = game.step[:state]
    expect(left[:ship][2]).to be_within(0.001).of((first[:ship][2] - (Math::PI / 4)) % (Math::PI * 2))
    game.key(:right)
    expect(game.step[:state][:ship][2]).to be_within(0.001).of(first[:ship][2])
    game.key(:up)
    moved = game.step[:state]
    expect(moved[:ship].take(2)).not_to eq(first[:ship].take(2))
    distance = moved[:ship].take(2).zip(first[:ship]).sum { |a, b| (a - b)**2 }
    expect(Math.sqrt(distance)).to be >= 0.079
    expect(moved[:thrust]).to be(true)
    game.key(:down)
    expect(game.step[:state][:thrust]).to be(true)
    game.key(' ')
    expect(game.step[:state][:shots].length).to eq(1)
  end
end

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
    [5, 8, 16, 20].product([1, 73, 74], [true, false]).each do |size, seed, branding|
      args = { name: :falling_blocks, width: size, height: size, seed: seed, branding: branding }
      frames = described_class.send(:mini_replay, **args, height: size + (branding ? 0 : 1))
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
          expect(x).to be_between(0, size - 1)
          expect(y).to be_between(0, ((size - (branding ? 1 : 0)) * 2) - 1)
          cell = cells[(branding ? 1 : 0) + (y / 2)][x]
          mask = ' ▘▝▀▖▌▞▛▗▚▐▜▄▙▟█'.index(cell[:glyph])
          actual = mask[(y % 2) * 2] == 1 ? cell[:foreground] : cell[:background]
          expect(actual).to eq(color)
        end
        next unless frames[index + 1][:event] == :lock

        stack = frame[:state][:stack]
        expect(points.any? { |x, y| y == stack.length - 1 || stack[y + 1][x] != ' ' }).to be(true)
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

  it 'draws Asteroids on a finer two-by-four dot raster, including bottom and wrapped edges' do
    board = Array.new(5) { ' ' * 5 }
    4.times { |y| described_class.send(:mini_dot, board: board, x: 0, y: y, color: 0) }
    described_class.send(:mini_dot, board: board, x: 9, y: 19, color: 2)
    described_class.send(:mini_dot, board: board, x: 10, y: 20, color: 0)
    expect(described_class::MINI_PIXELS.fetch(board[0][0])).to eq(["\u2847", :cyan])
    expect(described_class::MINI_PIXELS.fetch(board[4][4])).to eq(["\u2880", :yellow])
    expect(board.join.chars.reject { |pixel| pixel == ' ' }.length).to eq(2)
  end

  it 'draws a filled connected fine-dot ship with a solid center in every heading' do
    8.times do |direction|
      frames = []
      described_class.send(:mini_asteroids_snapshot, frames: frames, width: 8, height: 7, ship: [4, 3, direction * Math::PI / 4], thrust: false, rocks: [], shots: [], sparks: [])
      points = []
      frames.first[:rows].drop(1).each_with_index do |row, y|
        row.chars.each_with_index do |pixel, x|
          next if pixel == ' '

          glyph = described_class::MINI_PIXELS.fetch(pixel).first
          expect(glyph.ord).to be_between(0x2801, 0x28ff)
          mask = glyph.ord - 0x2800
          [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2], [0, 3], [1, 3]].each_with_index do |(dx, dy), bit|
            points << [(x * 2) + dx, (y * 4) + dy] if mask[bit] == 1
          end
        end
      end
      expect(points.length).to be_between(10, 13)
      expect(points).to include([8, 12])
      expect(points.map(&:first).minmax.then { |a, b| b - a }).to be_between(3, 4)
      expect(points.map(&:last).minmax.then { |a, b| b - a }).to be_between(3, 4)
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

  it 'keeps rocks small and neutral with sparse fine-dot shots and thrust' do
    frames = []
    described_class.send(:mini_asteroids_snapshot, frames: frames, width: 8, height: 7, ship: [4, 3, 0], thrust: false,
                                                   rocks: [[1, 1, 0, 0, 0.5, 1]], shots: [], sparks: [])
    rock_pixels = frames.first[:rows].drop(1).flat_map(&:chars).reject { |pixel| pixel == ' ' || (pixel.ord - 4096) / 256 == 0 }
    expect(rock_pixels.map { |pixel| described_class::MINI_PIXELS.fetch(pixel)[1] }.uniq).to eq([:white])
    expect(rock_pixels.sum { |pixel| ((pixel.ord - 4096) % 256).digits(2).sum }).to eq(4)
  end

  it 'keeps a solid fine-dot ship and sparse subcell occupancy throughout tiny seeded replays' do
    [5, 8, 16].product([1, 73, 74]).each do |size, seed|
      frames = described_class.send(:mini_replay, name: :asteroids, width: size, height: size, seed: seed)
      frames.each do |frame|
        next unless frame[:state][:ship]

        pixels = frame[:rows].drop(1).flat_map(&:chars).reject { |pixel| pixel == ' ' }
        area = pixels.sum { |pixel| ((pixel.ord - 4096) % 256).digits(2).sum }
        ship = pixels.select { |pixel| (pixel.ord - 4096) / 256 == 0 }
        expect(ship.sum { |pixel| ((pixel.ord - 4096) % 256).digits(2).sum }).to be_between(10, 13)
        expect(area).to be <= 28
        # A lone dot can occupy a cell: measure ink area above, not full
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
      visible = thrust.count { |frame| frame[:rows].drop(1).join.chars.any? { |pixel| (pixel.ord - 4096) / 256 == 5 } }
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
              expect(cell[:glyph]).to match(/\A[ PWN█▀▄▌▐░▒·●▘▝▖▗▞▛▚▜▙▟ᗧᗤᗢᗣ│•✹═≈▰▱\u2800-\u28ff]\z/)
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
      expect(described_class.mini_names).to eq(%i[falling_blocks snake pacman asteroids galaga frogger])
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
      expect(described_class.mini_names.length).to eq(6)
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
