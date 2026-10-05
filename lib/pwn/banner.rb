# frozen_string_literal: true

module PWN
  # Static banners and pure, PWN-branded retro ASCII/color loops: falling_blocks,
  # snake, pong, and asteroids. mini_frame returns fresh rows on a borderless canvas;
  # use equal width and height (5..16) for complete square artwork. Dimensions
  # clamp to 0..16 (colored blocks: 0..64). Set branding: false for an unbranded
  # pane with the wordmark row reclaimed for play; tiny panes then stay blank. The caller
  # samples mini_names once per session and advances the explicit frame index
  # every mini_frame_seconds(name:) (0.05 for Pong/Asteroids, 0.1 otherwise).
  # mini_cells replays 1800 seeded gameplay
  # frames (MINI_FRAME_COUNT); mini_frame retains its legacy 60-frame ASCII loop.
  # These are decorative game simulations, not interactive games or telemetry.
  # mini_cells uses local Random.new with seed 73 by default; callers may keep
  # a different integer seed per session. Six immutable replays are cached.
  # Tetrominoes stack and clear; snake pursues food and grows; Pong rallies
  # include imperfect paddle tracking, misses and score pips between serves.
  # Blocks use horizontal half-cells with independent foreground/background
  # colors, filling the pane below PWN (up to 64 cells). Other games retain
  # quadrant pixels; snake stays centered with food/head color priority.
  # White line-clear flashes and game-over/reset wipes are intentional.
  # Pong uses half-cell motion and one-cell-high paddles without speeding up play.
  # Asteroids uses five-pixel cyan arrowheads on a half-cell grid, sparse small
  # white rocks, yellow shots and red thrust; wrapped collisions split real rocks.
  # Static Banner modules autoload only when needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Banner
    autoload :Anon, 'pwn/banner/anon'
    autoload :Bubble, 'pwn/banner/bubble'
    autoload :Cheshire, 'pwn/banner/cheshire'
    autoload :CodeCave, 'pwn/banner/code_cave'
    autoload :DontPanic, 'pwn/banner/dont_panic'
    autoload :ForkBomb, 'pwn/banner/fork_bomb'
    autoload :FSociety, 'pwn/banner/f_society'
    autoload :JmpEsp, 'pwn/banner/jmp_esp'
    autoload :Matrix, 'pwn/banner/matrix'
    autoload :Ninja, 'pwn/banner/ninja'
    autoload :OffTheAir, 'pwn/banner/off_the_air'
    autoload :Pirate, 'pwn/banner/pirate'
    autoload :Radare2, 'pwn/banner/radare2'
    autoload :Radare2AI, 'pwn/banner/radare2_ai'
    autoload :WhiteRabbit, 'pwn/banner/white_rabbit'

    # Bounded, square character canvases. The caller owns the surrounding border.
    MINI_WIDTH = 16
    MINI_HEIGHT = 16
    MINI_FRAME_SECONDS = 0.1
    MINI_FRAME_COUNT = 1800
    MINI_SEED = 73
    MINI_CACHE_LIMIT = 6
    MINI_ASCII_FRAME_COUNT = 60
    # Five quadrant pixels, not a scaled-down vector sprite. Eight stable headings
    # keep the nose legible even in the 5-column pane; physics still turns smoothly.
    MINI_SHIP = Array.new(8) do |heading|
      points = heading.even? ? [[-1, -1], [0, -1], [1, 0], [0, 1], [-1, 1]] : [[0, -1], [1, 0], [1, 1], [0, 1], [-1, 0]]
      (heading / 2).times { points = points.map { |x, y| [-y, x] } }
      points.map(&:freeze).freeze
    end.freeze

    # Compact replay pixels expand to fresh cells only at the API boundary.
    MINI_PIXELS = {
      ' ' => [' ', :blue], 'P' => ['P', :blue], 'W' => ['W', :blue], 'N' => ['N', :blue],
      'c' => ['█', :cyan], 'y' => ['█', :yellow], 'm' => ['█', :magenta],
      'b' => ['█', :blue], 'r' => ['█', :red], 'g' => ['█', :green],
      'w' => ['█', :white], 'f' => ['▄', :red], 'o' => ['▀', :yellow],
      'l' => ['▌', :cyan], 'q' => ['▐', :magenta], ':' => ['░', :blue]
    }.merge(%i[cyan magenta yellow white green red blue].each_with_index.flat_map do |color, index|
      ' ▘▝▀▖▌▞▛▗▚▐▜▄▙▟█'.chars.each_with_index.map do |glyph, mask|
        [(256 + (index * 16) + mask).chr(Encoding::UTF_8), [glyph, color]]
      end
    end.to_h).merge(%i[black cyan magenta yellow white green red blue].each_with_index.flat_map do |top, top_index|
      %i[black cyan magenta yellow white green red blue].each_with_index.map do |bottom, bottom_index|
        mask = (top == :black ? 0 : 3) | (bottom == :black ? 0 : 12)
        cell = if top == bottom
                 [top == :black ? ' ' : '█', top, :black]
               elsif top == :black
                 ['▄', bottom, :black]
               else
                 ['▀', top, bottom]
               end
        [(1024 + (((top_index * 8) + bottom_index) * 16) + mask).chr(Encoding::UTF_8), cell]
      end
    end.to_h).transform_values(&:freeze).freeze
    MINI_SHAPES = [
      [[0, 0], [1, 0], [2, 0], [3, 0]],
      [[0, 0], [1, 0], [0, 1], [1, 1]],
      [[0, 0], [1, 0], [2, 0], [1, 1]],
      [[0, 0], [0, 1], [1, 1], [2, 1]],
      [[2, 0], [0, 1], [1, 1], [2, 1]],
      [[1, 0], [2, 0], [0, 1], [1, 1]],
      [[0, 0], [1, 0], [1, 1], [2, 1]]
    ].map { |shape| shape.map(&:freeze).freeze }.freeze

    # Supported Method Parameters::
    # Return fresh ASCII rows for decorative retro loops, not interactive games.
    # Use equal width and height for a square; 5..16 retains the complete artwork.
    # Smaller panes degrade to a wordmark. Caller owns randomness, clock and IO.
    # PWN::Banner.mini_frame(
    #   name: 'optional - falling_blocks, snake, pong, or asteroids; defaults to falling_blocks',
    #   frame: 'optional - integer frame index, defaults to zero and wraps at 60',
    #   width: 'optional - output columns clamped to zero through 16, defaults to 16',
    #   height: 'optional - output rows clamped to zero through 16, defaults to 16',
    #   branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
    # )

    public_class_method def self.mini_frame(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      raise ArgumentError, "Unknown mini-banner: #{name}" unless mini_names.map(&:to_s).include?(name)

      phase = (opts[:frame] || 0).to_i % MINI_ASCII_FRAME_COUNT
      width = (opts[:width] || MINI_WIDTH).to_i.clamp(0, MINI_WIDTH)
      height = (opts[:height] || MINI_HEIGHT).to_i.clamp(0, MINI_HEIGHT)
      return [] if width.zero? || height.zero?

      branding = opts[:branding] != false
      return Array.new(height) { ' ' * width } if !branding && (width < 5 || height < 5)

      height += 1 unless branding
      rows = Array.new(height) { ' ' * width }
      rows[0] = 'PWN'[0, width].center(width)
      return rows if width < 5 || height < 5

      send("mini_#{name}", rows: rows, phase: phase, width: width, height: height)
      branding ? rows : rows.drop(1)
    end

    # Supported Method Parameters::
    # List animation names; callers may sample once and retain the session choice.
    # PWN::Banner.mini_names

    public_class_method def self.mini_names
      %i[falling_blocks snake pong asteroids]
    end

    # Supported Method Parameters::
    # Return the presentation interval; simulations preserve their gameplay speed.
    # PWN::Banner.mini_frame_seconds(
    #   name: 'optional - animation name, defaults to falling_blocks'
    # )

    public_class_method def self.mini_frame_seconds(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      raise ArgumentError, "Unknown mini-banner: #{name}" unless mini_names.map(&:to_s).include?(name)

      %w[pong asteroids].include?(name) ? 0.05 : MINI_FRAME_SECONDS
    end

    # Supported Method Parameters::
    # Return rows of single-column Unicode block cells, with named terminal colors.
    # Each fresh cell has glyph, foreground and background keys; no ANSI or IO.
    # Square means terminal-cell dimensions, not physical pixels. Caller owns borders.
    # Use mini_frame_seconds for cadence; 1800 frames span 90 or 180 seconds.
    # Colored blocks fill the canvas with half-cell pieces; other games cap at 16.
    # PWN::Banner.mini_cells(
    #   name: 'optional - falling_blocks, snake, pong, or asteroids; defaults to falling_blocks',
    #   frame: 'optional - integer index, defaults to zero and wraps at 1800',
    #   width: 'optional - columns clamped to 0..64 for blocks, 0..16 otherwise; defaults to 16',
    #   height: 'optional - rows clamped to 0..64 for blocks, 0..16 otherwise; defaults to 16',
    #   seed: 'optional - integer local PRNG seed, defaults to 73; retain per session',
    #   branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
    # )

    public_class_method def self.mini_cells(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      phase = (opts[:frame] || 0).to_i % MINI_FRAME_COUNT
      raise ArgumentError, "Unknown mini-banner: #{name}" unless mini_names.map(&:to_s).include?(name)

      limit = name == 'falling_blocks' ? 64 : MINI_WIDTH
      width = (opts[:width] || MINI_WIDTH).to_i.clamp(0, limit)
      height = (opts[:height] || MINI_HEIGHT).to_i.clamp(0, limit)
      return [] if width.zero? || height.zero?

      branding = opts[:branding] != false
      # Simulate one extra row before removing the legacy label, so every output
      # row belongs to gameplay without changing the public dimension limits.
      rows = if width < 5 || height < 5
               [branding ? 'PWN'[0, width].center(width) : ' ' * width] + Array.new(height - 1) { ' ' * width }
             else
               replay = mini_replay(name: name, width: width, height: height + (branding ? 0 : 1), seed: (opts[:seed] || MINI_SEED).to_i)
               branding ? replay[phase][:rows] : replay[phase][:rows].drop(1)
             end
      rows.map do |row|
        row.chars.map do |pixel|
          glyph, foreground, background = MINI_PIXELS.fetch(pixel)
          { glyph: glyph.dup, foreground: foreground, background: background || :black }
        end
      end
    end

    # Caller-owned simulation: yields on the UI thread, never reads input or
    # accumulates a replay. The caller supplies the clock and normalized keys.
    class MiniGame
      def initialize(name:, width:, height:, seed: MINI_SEED)
        @name = name.to_s
        raise ArgumentError, "Unknown mini-banner: #{name}" unless Banner.mini_names.map(&:to_s).include?(@name)

        limit = @name == 'falling_blocks' ? 64 : MINI_WIDTH
        @width = width.clamp(5, limit)
        @height = height.clamp(5, limit)
        @keys = []
        @simulation = Fiber.new do
          options = { frames: self, width: @width, height: @name == 'falling_blocks' ? @height * 2 : @height,
                      rng: Random.new(seed), player: self }
          Banner.send("mini_simulate_#{@name}", options)
        end
      end

      def key(key)
        @keys << key if @keys.length < 16
      end

      def controls
        keys = @keys
        @keys = []
        keys
      end

      def step
        @simulation.resume
      end

      def cells(frame)
        rows = frame[:rows].drop(1)
        rows = Banner.send(:mini_block_board, board: rows) if @name == 'falling_blocks'
        rows = Banner.send(:mini_quarter_board, board: rows, name: @name) if @name == 'snake'
        rows.map do |row|
          row.chars.map do |pixel|
            glyph, foreground, background = MINI_PIXELS.fetch(pixel)
            { glyph: glyph.dup, foreground: foreground, background: background || :black }
          end
        end
      end

      def <<(frame)
        Fiber.yield(frame)
      end

      def length
        0
      end
    end

    # Six immutable, compact replays bound memory even when callers resize/reseed.
    private_class_method def self.mini_replay(opts = {})
      key = [opts[:name].to_s.dup.freeze, opts[:width], opts[:height], opts[:seed]].freeze
      @mini_replays ||= {}
      return @mini_replays[key] if @mini_replays.key?(key)

      name, width, height, seed = key
      # Two independently colored horizontal halves per terminal cell. Four
      # independent quadrants can require more than the terminal's two colors.
      # Keep full pane width and the bottom half-row, below the wordmark.
      height = ((height - 1) * 2) + 1 if name == 'falling_blocks'
      frames = []
      blank = Array.new(height - 1) { ' ' * width }
      mini_emit(frames: frames, board: blank, event: :ready, ticks: 6)
      send("mini_simulate_#{name}", frames: frames, width: width, height: height - 1, rng: Random.new(seed))
      # A white hold and top-to-bottom wipe explicitly mark the replay boundary.
      frames = frames.take(MINI_FRAME_COUNT - height - 6)
      board = frames.last[:rows].drop(1).map { |row| row.gsub(/[^ ]/, 'w') }
      mini_emit(frames: frames, board: board, event: :reset, ticks: 6)
      board.length.times do |y|
        board[y] = ' ' * width
        mini_emit(frames: frames, board: board, event: :reset)
      end
      mini_emit(frames: frames, board: blank, event: :ready)
      if %w[falling_blocks snake].include?(name)
        packed = {}.compare_by_identity
        frames = frames.map do |frame|
          packed[frame] ||= begin
            board = if name == 'falling_blocks'
                      mini_block_board(board: frame[:rows].drop(1))
                    else
                      mini_quarter_board(board: frame[:rows].drop(1), name: name)
                    end
            mini_freeze(value: frame.merge(rows: ['PWN'.center(board.first.length)] + board))
          end
        end
      end
      @mini_replays.shift while @mini_replays.length >= MINI_CACHE_LIMIT
      @mini_replays[key] = frames.freeze
    end

    private_class_method def self.mini_freeze(opts = {})
      value = opts[:value]
      case value
      when Hash
        value.each_value { |child| mini_freeze(value: child) }
      when Array
        value.each { |child| mini_freeze(value: child) }
      end
      value.freeze
    end

    # Each block occupies a horizontal half-cell for its entire lifetime. Unlike
    # four independent quadrants, two halves always fit foreground/background,
    # including differently colored neighbors, holes and white clear flashes.
    private_class_method def self.mini_block_board(opts = {})
      opts[:board].each_slice(2).map do |top, bottom|
        top.chars.each_with_index.map do |pixel, x|
          a = ' cmywgrb'.index(pixel)
          b = ' cmywgrb'.index(bottom[x])
          mask = (a.zero? ? 0 : 3) | (b.zero? ? 0 : 12)
          mask.zero? ? ' ' : (1024 + (((a * 8) + b) * 16) + mask).chr(Encoding::UTF_8)
        end.join
      end
    end

    # Retain snake's centered quadrant presentation.
    # A foreground-on-black terminal cell cannot show several colors plus black:
    # merge occupancy rather than erasing neighboring pieces/body at color seams.
    private_class_method def self.mini_quarter_board(opts = {})
      source = opts[:board]
      width = source.first.length
      height = source.length

      board = Array.new(height) { ' ' * width }
      colors = { 'c' => 0, 'm' => 1, 'y' => 2, 'w' => 3, 'g' => 4, 'r' => 5, 'f' => 5, 'b' => 6 }
      points = source.each_with_index.flat_map do |row, y|
        row.chars.each_with_index.filter_map { |pixel, x| [x, y, pixel] unless pixel == ' ' }
      end
      points.sort_by! { |_, _, pixel| { 'f' => 2, 'y' => 1 }.fetch(pixel, 0) } if opts[:name] == 'snake'
      points.each do |x, y, pixel|
        mini_pixel(board: board, x: x + (width / 2), y: y + (height / 2), color: colors.fetch(pixel), merge: true)
      end
      board
    end

    private_class_method def self.mini_emit(opts = {})
      board = opts[:board]
      rows = ['PWN'.center(board.first.length)] + board.map(&:dup)
      record = { rows: rows, event: opts[:event] || :play, state: opts[:state] || {} }
      mini_freeze(value: record)
      (opts[:ticks] || 1).times { opts[:frames] << record }
    end

    private_class_method def self.mini_rotations(opts = {})
      shape = opts[:shape]
      Array.new(4) do
        current = shape
        rotated = shape.map { |x, y| [-y, x] }
        min_x = rotated.map(&:first).min
        min_y = rotated.map(&:last).min
        shape = rotated.map { |x, y| [x - min_x, y - min_y] }.sort
        current
      end.uniq
    end

    private_class_method def self.mini_fits?(opts = {})
      board = opts[:board]
      opts[:shape].all? do |dx, dy|
        x = opts[:x] + dx
        y = opts[:y] + dy
        x >= 0 && x < board.first.length && y >= 0 && y < board.length && board[y][x] == ' '
      end
    end

    private_class_method def self.mini_landing(opts = {})
      board = opts[:board]
      rng = opts[:rng]
      candidates = []
      rotations = mini_rotations(shape: opts[:shape])
      spawn_x = (board.first.length - opts[:shape].map(&:first).max - 1) / 2
      rotations.each_with_index do |shape, rotation|
        # Only plan maneuvers the displayed spawn/rotate/steer sequence can make.
        # An obstructed rotation is rejected, never mistaken for a top-out.
        break unless mini_fits?(board: board, shape: shape, x: spawn_x, y: 0)

        (board.first.length - shape.map(&:first).max).times do |x|
          corridor = [spawn_x, x].min..[spawn_x, x].max
          next unless corridor.all? { |px| mini_fits?(board: board, shape: shape, x: px, y: 0) }

          y = 0
          y += 1 while mini_fits?(board: board, shape: shape, x: x, y: y + 1)
          test = board.map(&:dup)
          shape.each { |dx, dy| test[y + dy][x + dx] = 'c' }
          lines = test.count { |row| !row.include?(' ') }
          heights = []
          holes = 0
          board.first.length.times do |column|
            top = test.index { |row| row[column] != ' ' } || test.length
            heights << (test.length - top)
            holes += test.drop(top).count { |row| row[column] == ' ' }
          end
          score = (lines * 12) - (holes * 9) - (heights.sum * 0.65) - (heights.each_cons(2).sum { |a, b| (a - b).abs } * 0.5) + (rng.rand * 1.4)
          candidates << { shape: shape, rotation: rotation, x: x, y: y, score: score }
        end
      end
      candidates.max_by { |candidate| candidate[:score] }
    end

    private_class_method def self.mini_simulate_falling_blocks(opts = {})
      frames = opts[:frames]
      width = opts[:width]
      height = opts[:height]
      rng = opts[:rng]
      board = Array.new(height) { ' ' * width }
      bag = []
      while frames.length < MINI_FRAME_COUNT
        bag = (0...MINI_SHAPES.length).to_a.shuffle(random: rng) if bag.empty?
        type = bag.shift
        shape = MINI_SHAPES[type]
        landing = opts[:player] ? {} : mini_landing(board: board, shape: shape, rng: rng)
        x = (width - shape.map(&:first).max - 1) / 2
        unless landing && mini_fits?(board: board, shape: shape, x: x, y: 0)
          mini_reset_board(frames: frames, board: board)
          board = Array.new(height) { ' ' * width }
          next
        end
        if opts[:player]
          shape, x, y = mini_play_piece(board: board, type: type, frames: frames, player: opts[:player])
          landing = { x: x, y: y }
        else
          shape, x = mini_block_plan(board: board, shape: shape, x: x, landing: landing, frames: frames, type: type)
          unless shape
            mini_reset_board(frames: frames, board: board)
            board = Array.new(height) { ' ' * width }
            next
          end
        end
        color = %w[c y m b r g g][type]
        shape.each { |dx, dy| board[landing[:y] + dy][x + dx] = color }
        mini_emit(frames: frames, board: board, event: :lock, ticks: 2)
        full = board.each_index.reject { |row| board[row].include?(' ') }
        next if full.empty?

        flash = board.map(&:dup)
        full.each { |row| flash[row] = 'w' * width }
        mini_emit(frames: frames, board: flash, event: :clear, state: { lines: full }, ticks: 3)
        board = Array.new(full.length) { ' ' * width } + board.each_with_index.filter_map { |row, index| row unless full.include?(index) }
        mini_emit(frames: frames, board: board, event: :collapse, ticks: 2)
      end
    end

    private_class_method def self.mini_block_plan(opts = {})
      board, shape, x, landing, frames, type = opts.values_at(:board, :shape, :x, :landing, :frames, :type)
      rotations = mini_rotations(shape: shape)
      plan = [[shape, x, 0]]
      blocked = false
      (1..landing[:rotation]).each do |rotation|
        shape = rotations[rotation]
        if mini_fits?(board: board, shape: shape, x: x, y: 0)
          plan << [shape, x, 0]
        else
          blocked = true
        end
      end
      until x == landing[:x] || blocked
        x += landing[:x] <=> x
        blocked = !mini_fits?(board: board, shape: shape, x: x, y: 0)
        plan << [shape, x, 0] unless blocked
      end
      return if blocked

      (1..landing[:y]).each { |y| plan << [shape, x, y] }
      color = %w[c y m b r g g][type]
      plan.each do |piece, px, py|
        picture = board.map(&:dup)
        active = piece.map { |dx, dy| [px + dx, py + dy] }
        active.each { |ax, ay| picture[ay][ax] = color }
        mini_emit(frames: frames, board: picture,
                  state: { active: active, stack: board.map(&:dup), type: type })
      end
      [shape, x]
    end

    private_class_method def self.mini_play_piece(opts = {})
      board, type, frames, player = opts.values_at(:board, :type, :frames, :player)
      shape = MINI_SHAPES[type]
      x = (board.first.length - shape.map(&:first).max - 1) / 2
      y = 0
      tick = 0
      loop do
        active = shape.map { |dx, dy| [x + dx, y + dy] }
        picture = board.map(&:dup)
        active.each { |ax, ay| picture[ay][ax] = %w[c y m b r g g][type] }
        mini_emit(frames: frames, board: picture, state: { active: active, stack: board.map(&:dup), type: type })
        keys = player.controls
        keys.each do |key|
          candidate = key == ' ' ? mini_rotations(shape: shape).fetch(1, shape) : shape
          nx = x + { left: -1, right: 1 }.fetch(key, 0)
          next unless mini_fits?(board: board, shape: candidate, x: nx, y: y)

          shape = candidate
          x = nx
        end
        tick += 1
        next unless keys.include?(:down) || (tick % 5).zero?
        break unless mini_fits?(board: board, shape: shape, x: x, y: y + 1)

        y += 1
      end
      [shape, x, y]
    end

    private_class_method def self.mini_reset_board(opts = {})
      board = opts[:board].map { |row| row.gsub(/[^ ]/, 'w') }
      mini_emit(frames: opts[:frames], board: board, event: :game_over, ticks: 8)
      board.length.times do |y|
        board[y] = ' ' * board.first.length
        mini_emit(frames: opts[:frames], board: board, event: :reset)
      end
      mini_emit(frames: opts[:frames], board: board, event: :ready, ticks: 4)
    end

    private_class_method def self.mini_snake_route(opts = {})
      body = opts[:body]
      food = opts[:food]
      width = opts[:width]
      height = opts[:height]
      rng = opts[:rng]
      queue = [[body.first, nil]]
      seen = body.take(body.length - 1).to_h { |point| [point, true] }
      directions = [[1, 0], [-1, 0], [0, 1], [0, -1]].shuffle(random: rng)
      cursor = 0
      while cursor < queue.length
        point, first = queue[cursor]
        cursor += 1
        return first if point == food

        directions.each do |dx, dy|
          target = [point[0] + dx, point[1] + dy]
          next unless target[0].between?(0, width - 1) && target[1].between?(0, height - 1)
          next if seen[target]

          seen[target] = true
          queue << [target, first || target]
        end
      end
      directions.map { |dx, dy| [body.first[0] + dx, body.first[1] + dy] }.find do |point|
        point[0].between?(0, width - 1) && point[1].between?(0, height - 1) && !body.take(body.length - 1).include?(point)
      end
    end

    private_class_method def self.mini_simulate_snake(opts = {})
      frames = opts[:frames]
      width = opts[:width]
      height = opts[:height]
      rng = opts[:rng]
      spaces = (0...height).flat_map { |y| (0...width).map { |x| [x, y] } }
      player = opts[:player]
      while frames.length < MINI_FRAME_COUNT
        y = rng.rand(height)
        body = [[2, y], [1, y], [0, y]]
        direction = [1, 0]
        food = (spaces - body).sample(random: rng)
        steps = 0
        loop do
          board = Array.new(height) { ' ' * width }
          body.each_with_index { |(x, row), index| board[row][x] = index.zero? ? 'y' : 'g' }
          board[food[1]][food[0]] = 'f' if food
          mini_emit(frames: frames, board: board, ticks: player ? 1 : 2, state: { body: body.map(&:dup), food: food&.dup })
          break if frames.length >= MINI_FRAME_COUNT

          if player
            turn = player.controls.filter_map { |key| { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] }[key] }.find do |dx, dy|
              [dx, dy] != direction && [dx, dy] != direction.map(&:-@)
            end
            direction = turn if turn
            target = [body.first[0] + direction[0], body.first[1] + direction[1]]
            occupied = target == food ? body : body.take(body.length - 1)
            target = nil unless spaces.include?(target) && !occupied.include?(target)
          elsif food
            target = mini_snake_route(body: body, food: food, width: width, height: height, rng: rng)
          end
          if !food || !target || steps >= width * height * 4
            mini_reset_board(frames: frames, board: board)
            break
          end
          body.unshift(target)
          if target == food
            food = (spaces - body).sample(random: rng)
            steps = 0
          else
            body.pop
            steps += 1
          end
        end
      end
    end

    private_class_method def self.mini_simulate_pong(opts = {})
      frames = opts[:frames]
      width = opts[:width]
      height = opts[:height]
      rng = opts[:rng]
      paddles = [(height - 1) / 2.0, (height - 1) / 2.0]
      player = opts[:player]
      scores = [0, 0]
      while frames.length < MINI_FRAME_COUNT
        x = (width - 1) / 2.0
        y = rng.rand(1...(height - 1)).to_f
        vx = (rng.rand(2).zero? ? -1 : 1) * 0.325
        vy = ((rng.rand * 0.4) + 0.1) * (rng.rand(2).zero? ? -1 : 1)
        bias = Array.new(2) { rng.rand(5).zero? ? rng.rand(-2..2) : rng.rand - 0.5 }
        rally = 0
        mini_pong_snapshot(frames: frames, width: width, height: height, paddles: paddles, ball: [x, y], scores: scores, event: :serve, ticks: player ? 1 : 16)
        loop do
          player&.controls&.each do |key|
            paddles[0] = (paddles[0] + { up: -0.5, down: 0.5 }.fetch(key, 0)).clamp(0, height - 1)
          end
          paddles.each_index do |side|
            next if player && side.zero?

            incoming = side.zero? ? vx.negative? : vx.positive?
            target = incoming ? y - 0.25 + bias[side] : (height - 1) / 2.0
            speed = incoming ? 0.275 : 0.11
            paddles[side] = (paddles[side] + (target - paddles[side]).clamp(-speed, speed)).clamp(0, height - 1)
          end
          nx = x + vx
          ny = y + vy
          if ny.negative? || ny > height - 1
            ny = ny.negative? ? -ny : (2 * (height - 1)) - ny
            vy = -vy
          end
          side = if x >= 1 && nx < 1
                   0
                 elsif x <= width - 2 && nx > width - 2
                   1
                 end
          event = :play
          if side && (ny - paddles[side]).between?(-0.25, 0.75)
            nx = side.zero? ? 2 - nx : (2 * (width - 2)) - nx
            vx = -vx
            offset = ny - (paddles[side] + 0.25)
            vy = ((offset * 0.65) + (rng.rand * 0.15) - 0.075).clamp(-0.4, 0.4)
            vy = (rng.rand(2).zero? ? -0.11 : 0.11) if vy.abs < 0.075
            bias[1 - side] = rng.rand(5).zero? ? rng.rand(-2..2) : rng.rand - 0.5
            rally += 1
            event = :bounce
          end
          x = nx
          y = ny
          if x.negative? || x > width - 1
            scores[x.negative? ? 1 : 0] += 1
            mini_pong_snapshot(frames: frames, width: width, height: height, paddles: paddles, ball: nil, scores: scores, event: :score, ticks: player ? 1 : 20)
            break
          end
          mini_pong_snapshot(frames: frames, width: width, height: height, paddles: paddles, ball: [x, y], scores: scores, event: event, rally: rally)
          break if frames.length >= MINI_FRAME_COUNT
        end
      end
    end

    private_class_method def self.mini_pong_snapshot(opts = {})
      width, height, paddles, ball, scores = opts.values_at(:width, :height, :paddles, :ball, :scores)
      board = Array.new(height) { ' ' * width }
      height.times { |y| board[y][width / 2] = ':' if y.even? }
      paddles.each_with_index do |top, side|
        2.times do |dy|
          mini_pixel(board: board, x: side.zero? ? 0 : (width * 2) - 1, y: (top * 2).floor + dy, color: side)
        end
      end
      mini_pixel(board: board, x: (ball[0] * 2).round, y: (ball[1] * 2).round, color: 2) if ball
      if opts[:event] == :score
        [scores[0], (width - 1) / 2].min.times { |x| board[0][x] = 'c' }
        [scores[1], (width - 1) / 2].min.times { |x| board[0][width - 1 - x] = 'm' }
      end
      mini_emit(frames: opts[:frames], board: board, event: opts[:event], ticks: opts[:ticks],
                state: { ball: ball&.dup, paddles: paddles.dup, paddle_height: 1.0, scores: scores.dup, rally: opts[:rally] || 0 })
    end

    # Two-by-two quadrant pixels: same-color neighbors coalesce, no ANSI/IO.
    private_class_method def self.mini_pixel(opts = {})
      board = opts[:board]
      x = opts[:x] % (board.first.length * 2)
      y = opts[:y] % (board.length * 2)
      color = opts[:color]
      prior = board[y / 2][x / 2].ord - 256
      mask = prior >= 0 && (opts[:merge] || prior / 16 == color) ? prior % 16 : 0
      mask |= 1 << ((y % 2 * 2) + (x % 2))
      board[y / 2][x / 2] = (256 + (color * 16) + mask).chr(Encoding::UTF_8)
    end

    private_class_method def self.mini_simulate_asteroids(opts = {})
      frames, width, height, rng = opts.values_at(:frames, :width, :height, :rng)
      ship = [width / 2.0, height / 2.0, rng.rand * Math::PI * 2]
      velocity = [0.0, 0.0]
      rocks = []
      shots = []
      sparks = []
      serial = 0
      tick = 0
      while frames.length < MINI_FRAME_COUNT
        event = :play
        # Reserve room for both fragments before spawning a large rock.
        rock_budget = [3, width / 4].min + 1
        occupied = rocks.sum { |rock| rock[4] > 0.25 ? 2 : 1 }
        if rocks.empty? || ((tick % 120).zero? && occupied + 2 <= rock_budget)
          serial += 1
          x = rng.rand * width
          y = rng.rand * height
          dx = mini_delta(from: ship[0], to: x, span: width)
          dy = mini_delta(from: ship[1], to: y, span: height)
          if (dx * dx) + (dy * dy) < 1.5**2
            x = (x + (width / 2.0)) % width
            y = (y + (height / 2.0)) % height
          end
          rocks << [x, y, (rng.rand - 0.5) * 0.12, (rng.rand - 0.5) * 0.12, 0.5, serial]
          event = :respawn
        end
        rocks.each do |rock|
          rock[0] = (rock[0] + rock[2]) % width
          rock[1] = (rock[1] + rock[3]) % height
        end
        target = rocks.min_by do |rock|
          (mini_delta(from: ship[0], to: rock[0], span: width)**2) + (mini_delta(from: ship[1], to: rock[1], span: height)**2)
        end
        angle = Math.atan2(mini_delta(from: ship[1], to: target[1], span: height), mini_delta(from: ship[0], to: target[0], span: width))
        turn = mini_delta(from: ship[2], to: angle, span: Math::PI * 2).clamp(-0.1, 0.1)
        keys = opts[:player]&.controls
        turn = keys.sum { |key| { left: -0.2, right: 0.2 }.fetch(key, 0) } if keys
        ship[2] = (ship[2] + turn) % (Math::PI * 2)
        power = tick % 80 < 24 ? 1 : 0
        power = keys.sum { |key| { up: 1, down: -1 }.fetch(key, 0) }.clamp(-1, 1) if keys
        thrust = !power.zero?
        [Math.cos(ship[2]), Math.sin(ship[2])].each_with_index do |direction, axis|
          velocity[axis] = ((velocity[axis] * 0.99) + (direction * 0.006 * power)).clamp(-0.15, 0.15)
          ship[axis] = (ship[axis] + velocity[axis]) % (axis.zero? ? width : height)
        end
        fire = keys ? keys.include?(' ') : (tick % 12).zero?
        shots << [ship[0], ship[1], Math.cos(ship[2]) * 0.36, Math.sin(ship[2]) * 0.36, 24] if fire
        shots.each do |shot|
          shot[0] = (shot[0] + shot[2]) % width
          shot[1] = (shot[1] + shot[3]) % height
          shot[4] -= 1
          hit = rocks.find do |rock|
            dx = mini_delta(from: shot[0], to: rock[0], span: width)
            dy = mini_delta(from: shot[1], to: rock[1], span: height)
            (dx * dx) + (dy * dy) <= rock[4]**2
          end
          next unless hit

          rocks.delete(hit)
          shot[4] = 0
          sparks << [hit[0], hit[1], 8]
          if hit[4] > 0.25
            [-1, 1].each do |sign|
              serial += 1
              rocks << [hit[0], hit[1], hit[2] + (sign * 0.07), hit[3] - (sign * 0.05), 0.2, serial]
            end
          end
          event = :hit
        end
        shots.reject! { |shot| shot[4] <= 0 }
        sparks.each { |spark| spark[2] -= 1 }
        sparks.reject! { |spark| spark[2] <= 0 }
        mini_asteroids_snapshot(frames: frames, width: width, height: height, ship: ship, thrust: thrust,
                                rocks: rocks, shots: shots, sparks: sparks, event: event)
        tick += 1
      end
    end

    private_class_method def self.mini_delta(opts = {})
      span = opts[:span]
      ((opts[:to] - opts[:from] + (span / 2.0)) % span) - (span / 2.0)
    end

    private_class_method def self.mini_asteroids_snapshot(opts = {})
      width, height, ship, rocks, shots, sparks = opts.values_at(:width, :height, :ship, :rocks, :shots, :sparks)
      board = Array.new(height) { ' ' * width }
      rocks.each do |rock|
        x, y, radius = rock.values_at(0, 1, 4)
        count = radius > 0.25 ? 4 : 1
        count.times do |index|
          angle = index * Math::PI * 2 / count
          dx = count == 1 ? 0 : Math.cos(angle) * radius
          dy = count == 1 ? 0 : Math.sin(angle) * radius
          mini_pixel(board: board, x: ((x + dx) * 2).round, y: ((y + dy) * 2).round, color: 3)
        end
      end
      sparks.each do |x, y, life|
        2.times do |index|
          angle = index * Math::PI
          radius = (8 - life) * 0.12
          mini_pixel(board: board, x: ((x + (Math.cos(angle) * radius)) * 2).round, y: ((y + (Math.sin(angle) * radius)) * 2).round, color: 3)
        end
      end
      shots.each { |x, y,| mini_pixel(board: board, x: (x * 2).round, y: (y * 2).round, color: 2) }
      if opts[:thrust]
        # A black subpixel gap separates exhaust from hull: a terminal cell has
        # only two colors, so cyan/red/black in one quadrant glyph loses the red.
        mini_pixel(board: board, x: ((ship[0] * 2) - (Math.cos(ship[2]) * 3)).round,
                   y: ((ship[1] * 2) - (Math.sin(ship[2]) * 3)).round, color: 5)
      end
      MINI_SHIP[(ship[2] * 4 / Math::PI).round % 8].each do |dx, dy|
        mini_pixel(board: board, x: (ship[0] * 2).round + dx, y: (ship[1] * 2).round + dy, color: 0)
      end
      mini_emit(frames: opts[:frames], board: board, event: opts[:event],
                state: { ship: ship.dup, thrust: opts[:thrust], rocks: rocks.map(&:dup), shots: shots.map(&:dup) })
    end

    private_class_method def self.mini_asteroids(opts = {})
      rows, phase, width, height = opts.values_at(:rows, :phase, :width, :height)
      3.times { |index| rows[1 + (((phase / 3) + index) % (height - 1))][((phase / 2) + (index * 3)) % width] = 'O' }
      rows[height / 2][width / 2] = %w[> v < ^][phase / 15]
      rows[1 + ((phase / 2) % (height - 1))][((width / 2) + phase) % width] = '.'
    end

    private_class_method def self.mini_falling_blocks(opts = {})
      rows = opts[:rows]
      phase = opts[:phase]
      width = opts[:width]
      height = opts[:height]
      # Alternating T and O tetrominoes complete two prepared rows, then clear.
      shape = phase < 30 ? ['###', ' # '] : ['##', '##']
      tick = phase % 30
      left = (width - shape.first.length) / 2
      shape.each_with_index do |line, dy|
        rows[height - 2 + dy] = '#' * width
        line.chars.each_with_index do |cell, dx|
          rows[height - 2 + dy][left + dx] = ' ' if cell == '#'
        end
      end
      top = 1 + ([tick, 24].min * (height - 3) / 24)
      shape.each_with_index do |line, dy|
        line.chars.each_with_index { |cell, dx| rows[top + dy][left + dx] = cell if cell == '#' }
      end
      return unless tick >= 26

      rows[-2] = rows[-1] = (tick.even? ? '=' : ' ') * width
      # Do not alias caller-mutable strings across rows, including clear frames.
      rows[-1] = rows[-1].dup
    end

    private_class_method def self.mini_snake(opts = {})
      rows = opts[:rows]
      width = opts[:width]
      height = opts[:height]
      # A closed perimeter path keeps both the body and the cycle seam contiguous.
      path = (0...width).map { |x| [x, 1] }
      path += (2...height).map { |y| [width - 1, y] }
      path += (0...(width - 1)).to_a.reverse.map { |x| [x, height - 1] }
      path += (2...(height - 1)).to_a.reverse.map { |y| [0, y] }
      head = opts[:phase] * path.length / MINI_ASCII_FRAME_COUNT
      rows[height / 2][width / 2] = '*'
      [width, 7].min.times do |offset|
        x, y = path[(head - offset) % path.length]
        rows[y][x] = offset.zero? ? '@' : 'o'
      end
    end

    private_class_method def self.mini_pong(opts = {})
      rows = opts[:rows]
      width = opts[:width]
      height = opts[:height]
      phase = opts[:phase]
      # Triangle waves reflect the ball, with no teleport at the cycle boundary.
      x = 1 + ((30 - (phase - 30).abs) * (width - 3) / 30)
      y = 1 + ((15 - ((phase % 30) - 15).abs) * (height - 2) / 15)
      (1...height).each { |row| rows[row][width / 2] = ':' if row.odd? }
      paddle_top = y.clamp(1, height - 2)
      (paddle_top..(paddle_top + 1)).each do |row|
        rows[row][0] = '|'
        rows[row][width - 1] = '|'
      end
      rows[y][x] = 'o'
    end

    # Supported Method Parameters::
    # PWN::Banner.get(
    #   index: 'optional - defaults to random banner index'
    # )

    public_class_method def self.get(opts = {})
      index = opts[:index].to_i
      index = Random.rand(1..15) unless index.positive?

      banner = ''
      case index
      when 1
        banner = PWN::Banner::Anon.get
      when 2
        banner = PWN::Banner::Bubble.get
      when 3
        banner = PWN::Banner::Cheshire.get
      when 4
        banner = PWN::Banner::CodeCave.get
      when 5
        banner = PWN::Banner::DontPanic.get
      when 6
        banner = PWN::Banner::ForkBomb.get
      when 7
        banner = PWN::Banner::FSociety.get
      when 8
        banner = PWN::Banner::JmpEsp.get
      when 9
        banner = PWN::Banner::Matrix.get
      when 10
        banner = PWN::Banner::Ninja.get
      when 11
        banner = PWN::Banner::OffTheAir.get
      when 12
        banner = PWN::Banner::Pirate.get
      when 13
        banner = PWN::Banner::Radare2.get
      when 14
        banner = PWN::Banner::Radare2AI.get
      when 15
        banner = PWN::Banner::WhiteRabbit.get
      else
        raise 'Invalid Index.'
      end

      banner
    end

    # Supported Method Parameters::
    # PWN::Banner.get(
    #   index: 'optional - defaults to random banner index'
    # )

    public_class_method def self.welcome
      banner = PWN::Banner.get
      banner = "#{banner}\nUse the #help command & methods for more options.\n"
      banner = "#{banner}e.g help\n"
      banner = "#{banner}e.g PWN.help\n"
      banner = "#{banner}e.g PWN::Plugins.help\n"
      banner = "#{banner}e.g PWN::Plugins::TransparentBrowser.help\n"
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):
        0day Inc. <support@0dayinc.com>
      "
    end

    # Display Usage for this Module

    public_class_method def self.help
      puts "USAGE:
        # Run get and return its result
        #{self}.get(
          index: 'optional - defaults to random banner index'
        )

        # List compact animation names; sample once per session, not per redraw.
        #{self}.mini_names

        # Presentation cadence for colored games; ASCII keeps MINI_FRAME_SECONDS.
        #{self}.mini_frame_seconds(
          name: 'optional - animation name, defaults to falling_blocks'
        )

        # Return fresh ASCII rows; caller owns timing, theme, and terminal drawing.
        # Decorative retro loops, not interactive games or progress/telemetry.
        # Advance every MINI_FRAME_SECONDS (0.1 seconds); ASCII wraps at 60.
        # Pass equal width and height for a square; complete artwork fits 5..16.
        # No border is included. Smaller panes show only a clipped PWN wordmark.
        #{self}.mini_frame(
          name: 'optional - falling_blocks, snake, pong, or asteroids; defaults to falling_blocks',
          frame: 'optional - integer frame index, defaults to zero and wraps at 60',
          width: 'optional - columns clamped to zero through 16; defaults to 16',
          height: 'optional - rows clamped to zero through 16; defaults to 16',
          branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
        )

        # Return fresh Unicode block cells: { glyph:, foreground:, background: }.
        # Colors are standard terminal names; blocks may use colored backgrounds.
        # No ANSI or IO. Other games retain black backgrounds.
        # 1800 frames; mini_frame_seconds is 0.05 for Pong/Asteroids, 0.1 otherwise.
        # Caller samples mini_names once per session. No timers or animation threads.
        # Seeded gameplay, bounded six-replay cache; white hold/wipe marks resets.
        # Square refers to terminal cells, not physical pixels. Caller owns borders.
        #{self}.mini_cells(
          name: 'optional - falling_blocks, snake, pong, or asteroids; defaults to falling_blocks',
          frame: 'optional - integer frame index, defaults to zero and wraps at 1800',
          width: 'optional - columns clamped to 0..64 for blocks, 0..16 otherwise; defaults to 16',
          height: 'optional - rows clamped to 0..64 for blocks, 0..16 otherwise; defaults to 16',
          seed: 'optional - integer local PRNG seed, defaults to 73; retain per session',
          branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
        )

        # Run welcome and return its result
        #{self}.welcome

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
