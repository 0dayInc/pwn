# frozen_string_literal: true

module PWN
  # Static banners and pure, PWN-branded retro ASCII/color loops: falling_blocks,
  # snake, pacman, asteroids, galaga and frogger. mini_frame returns fresh rows on a borderless canvas;
  # use equal width and height (5..16) for complete square artwork. Dimensions
  # clamp to 0..16 (colored blocks/Pac-Man/Galaga/Frogger: 0..64). Set branding: false for an unbranded
  # pane with the wordmark row reclaimed for play; tiny panes then stay blank. The caller
  # samples mini_names once per session and advances the explicit frame index
  # every mini_frame_seconds(name:) (0.05 for Asteroids/Galaga, 0.1 otherwise).
  # mini_cells replays 1800 seeded gameplay
  # frames (MINI_FRAME_COUNT); mini_frame retains its legacy 60-frame ASCII loop.
  # Inactive panes use seeded demos; MiniGame supplies caller-owned playable state.
  # mini_cells uses local Random.new with seed 73 by default; callers may keep
  # a different integer seed per session. Six immutable replays are cached.
  # Tetrominoes stack and clear; snake pursues food and grows; Pac-Man eats pellets
  # in connected mazes with chasing ghosts, energizers, recovery and new levels.
  # Blocks use horizontal half-cells with independent foreground/background
  # colors, filling the pane below PWN (up to 64 cells). Other games retain
  # quadrant pixels; decorative snake stays centered with food/head color priority.
  # White line-clear flashes and game-over/reset wipes are intentional.
  # Pac-Man and ghosts occupy one cell each so even eight-cell panes retain
  # internal walls and corridors. Directional mouths and compact ghost glyphs
  # trade eye detail for maze geometry; spanning-tree mazes vary each round.
  # Galaga has formations, dives, hostile fire, explosions and advancing waves;
  # arrows move and Space fires. Frogger arrows hop through moving traffic and
  # onto carrying logs to fill goals, recover from deaths and advance levels.
  # Both start on input, run automatic demos when inactive and retain the UI owner.
  # Legacy name: :pong remains accepted by direct APIs but is not selectable.
  # Asteroids uses filled cyan ships on a 2x4 Braille raster, sparse small
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
    # Filled fine-dot silhouettes, with a solid spine and tapered nose. Eight headings
    # keep the nose legible even in the 5-column pane; physics still turns smoothly.
    MINI_SHIP = Array.new(8) do |heading|
      points = if heading.even?
                 [[-1, -2], [-1, -1], [0, -1], [-1, 0], [0, 0], [1, 0], [2, 0], [-1, 1], [0, 1], [-1, 2]]
               else
                 [[-1, -2], [-1, -1], [0, -1], [-2, -1], [-1, 0], [0, 0], [1, 0], [0, 1], [1, 1], [2, 2]]
               end
      (heading / 2).times { points = points.map { |x, y| [-y, x] } }
      points.map(&:freeze).freeze
    end.freeze

    # Compact replay pixels expand to fresh cells only at the API boundary.
    MINI_PIXELS = {
      ' ' => [' ', :blue], 'P' => ['P', :blue], 'W' => ['W', :blue], 'N' => ['N', :blue],
      'c' => ['█', :cyan], 'y' => ['█', :yellow], 'm' => ['█', :magenta],
      'b' => ['█', :blue], 'r' => ['█', :red], 'g' => ['█', :green],
      'w' => ['█', :white], 'f' => ['▄', :red], 'o' => ['▀', :yellow],
      'l' => ['▌', :cyan], 'q' => ['▐', :magenta], ':' => ['░', :blue],
      '#' => ['▒', :blue], '.' => ['·', :white], '*' => ['●', :yellow],
      '>' => ['ᗧ', :yellow], '<' => ['ᗤ', :yellow], '^' => ['ᗢ', :yellow], 'v' => ['ᗣ', :yellow],
      'O' => ['●', :yellow],
      'A' => ['⣾', :cyan], 'E' => ['⣜', :red], 'B' => ['⣷', :magenta],
      '!' => ['│', :yellow], 'i' => ['•', :red], '+' => ['✹', :yellow],
      'H' => ['⣏', :green], '=' => ['═', :yellow], '~' => ['≈', :blue], 'T' => ['▰', :red], 'U' => ['▱', :green],
      'R' => ['⣻', :red], 'M' => ['⣻', :magenta], 'C' => ['⣻', :cyan], 'F' => ['⣻', :blue]
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
    end.to_h).merge(%i[cyan magenta yellow white green red blue].each_with_index.flat_map do |color, index|
      256.times.map do |mask|
        [(4096 + (index * 256) + mask).chr(Encoding::UTF_8), [(0x2800 + mask).chr(Encoding::UTF_8), color]]
      end
    end.to_h).merge(%i[cyan magenta yellow white green red blue].each_with_index.flat_map do |color, index|
      [['•', :white, color], ['▙', color], ['▟', color], ['⠶', :white, color]].each_with_index.map do |cell, part|
        [(8000 + (index * 4) + part).chr(Encoding::UTF_8), cell]
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
    #   name: 'optional - falling_blocks, snake, pacman, asteroids, galaga or frogger; legacy pong accepted; defaults to falling_blocks',
    #   frame: 'optional - integer frame index, defaults to zero and wraps at 60',
    #   width: 'optional - output columns clamped to zero through 16, defaults to 16',
    #   height: 'optional - output rows clamped to zero through 16, defaults to 16',
    #   branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
    # )

    public_class_method def self.mini_frame(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      raise ArgumentError, "Unknown mini-banner: #{name}" unless (mini_names + [:pong]).map(&:to_s).include?(name)

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

      if %w[galaga frogger].include?(name)
        frame = mini_replay(name: name, width: width, height: height, seed: MINI_SEED)[phase + 6]
        frame[:rows].drop(1).each_with_index { |row, y| rows[y + 1] = row.tr('AEB!i+H=~TU', 'AVV|*!F=~CH').gsub(/[\u1000-\u16ff]/, 'A') }
      else
        send("mini_#{name}", rows: rows, phase: phase, width: width, height: height)
      end
      branding ? rows : rows.drop(1)
    end

    # Supported Method Parameters::
    # List animation names; callers may sample once and retain the session choice.
    # PWN::Banner.mini_names

    public_class_method def self.mini_names
      %i[falling_blocks snake pacman asteroids galaga frogger]
    end

    # Supported Method Parameters::
    # Return the presentation interval; simulations preserve their gameplay speed.
    # PWN::Banner.mini_frame_seconds(
    #   name: 'optional - animation name, defaults to falling_blocks'
    # )

    public_class_method def self.mini_frame_seconds(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      raise ArgumentError, "Unknown mini-banner: #{name}" unless (mini_names + [:pong]).map(&:to_s).include?(name)

      %w[pong asteroids galaga].include?(name) ? 0.05 : MINI_FRAME_SECONDS
    end

    # Supported Method Parameters::
    # Return rows of single-column Unicode block cells, with named terminal colors.
    # Each fresh cell has glyph, foreground and background keys; no ANSI or IO.
    # Square means terminal-cell dimensions, not physical pixels. Caller owns borders.
    # Use mini_frame_seconds for cadence; 1800 frames span 90 or 180 seconds.
    # Blocks, Pac-Man, Galaga and Frogger fill up to 64 cells; other games cap at 16.
    # PWN::Banner.mini_cells(
    #   name: 'optional - falling_blocks, snake, pacman, asteroids, galaga or frogger; legacy pong accepted; defaults to falling_blocks',
    #   frame: 'optional - integer index, defaults to zero and wraps at 1800',
    #   width: 'optional - columns clamped to 0..64 for blocks/Pac-Man/Galaga/Frogger, 0..16 otherwise; defaults to 16',
    #   height: 'optional - rows clamped to 0..64 for blocks/Pac-Man/Galaga/Frogger, 0..16 otherwise; defaults to 16',
    #   seed: 'optional - integer local PRNG seed, defaults to 73; retain per session',
    #   branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
    # )

    public_class_method def self.mini_cells(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      phase = (opts[:frame] || 0).to_i % MINI_FRAME_COUNT
      raise ArgumentError, "Unknown mini-banner: #{name}" unless (mini_names + [:pong]).map(&:to_s).include?(name)

      limit = %w[falling_blocks pacman galaga frogger].include?(name) ? 64 : MINI_WIDTH
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
    # demo: true supplies automatic controls without a full replay construction.
    class MiniGame
      def initialize(name:, width:, height:, seed: MINI_SEED, demo: false)
        @name = name.to_s
        raise ArgumentError, "Unknown mini-banner: #{name}" unless (Banner.mini_names + [:pong]).map(&:to_s).include?(@name)

        limit = %w[falling_blocks pacman galaga frogger].include?(@name) ? 64 : MINI_WIDTH
        @width = width.clamp(5, limit)
        @height = height.clamp(5, limit)
        @keys = []
        @simulation = Fiber.new do
          options = { frames: self, width: @name == 'snake' ? @width * 2 : @width, height: %w[falling_blocks snake].include?(@name) ? @height * 2 : @height,
                      rng: Random.new(seed), player: demo ? nil : self }
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
        rows = Banner.send(:mini_quarter_board, board: rows, name: @name, full: true) if @name == 'snake'
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

      board = Array.new(opts[:full] ? height / 2 : height) { ' ' * (opts[:full] ? width / 2 : width) }
      colors = { 'c' => 0, 'm' => 1, 'y' => 2, 'w' => 3, 'g' => 4, 'r' => 5, 'f' => 5, 'b' => 6 }
      points = source.each_with_index.flat_map do |row, y|
        row.chars.each_with_index.filter_map { |pixel, x| [x, y, pixel] unless pixel == ' ' }
      end
      points.sort_by! { |_, _, pixel| { 'f' => 2, 'y' => 1 }.fetch(pixel, 0) } if opts[:name] == 'snake'
      points.each do |x, y, pixel|
        mini_pixel(board: board, x: x + (opts[:full] ? 0 : width / 2), y: y + (opts[:full] ? 0 : height / 2), color: colors.fetch(pixel), merge: true)
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
        y = player ? height / 2 : rng.rand(height)
        body = [[2, y], [1, y], [0, y]]
        direction = [1, 0]
        food = (spaces - body).sample(random: rng)
        steps = 0
        started = !player
        loop do
          board = Array.new(height) { ' ' * width }
          body.each_with_index { |(x, row), index| board[row][x] = index.zero? ? 'y' : 'g' }
          board[food[1]][food[0]] = 'f' if food
          mini_emit(frames: frames, board: board, ticks: player ? 1 : 2, event: started ? :play : :ready, state: { body: body.map(&:dup), food: food&.dup })
          break if frames.length >= MINI_FRAME_COUNT

          if player
            keys = player.controls
            started ||= keys.intersect?(%i[up down left right])
            next unless started

            turn = keys.filter_map { |key| { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] }[key] }.find do |dx, dy|
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
            if player
              # Do not spend seconds in the decorative wipe ignoring arrows.
              # A brief collision flash is followed by another input-gated round.
              mini_emit(frames: frames, board: board.map { |row| row.gsub(/[^ ]/, 'w') }, event: :game_over)
            else
              mini_reset_board(frames: frames, board: board)
            end
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

    # A connected lattice with broad corridors and four corner energizers.
    # Even dimensions keep the final interior row/column open, too.
    private_class_method def self.mini_pacman_round(opts = {})
      width, height = opts.values_at(:width, :height)
      rng = opts[:rng] || Random.new(MINI_SEED)
      maze = Array.new(height) { '#' * width }
      maze[1][1] = ' '
      stack = [[1, 1]]
      # Randomized depth-first spanning tree, then braid extra loops. Every
      # opened cell touches the connected tree; no rejection flood fills.
      until stack.empty?
        x, y = stack.last
        choices = [[2, 0], [-2, 0], [0, 2], [0, -2]].select do |dx, dy|
          (x + dx).between?(1, width - 2) && (y + dy).between?(1, height - 2) && maze[y + dy][x + dx] == '#'
        end
        if choices.empty?
          stack.pop
        else
          dx, dy = choices.sample(random: rng)
          maze[y + (dy / 2)][x + (dx / 2)] = ' '
          maze[y + dy][x + dx] = ' '
          stack << [x + dx, y + dy]
        end
      end
      (1...(height - 1)).each do |y|
        (1...(width - 1)).each do |x|
          ring = x == 1 || y == 1 || x == width - 2 || y == height - 2
          maze[y][x] = ' ' if ring || (rng.rand < 0.18 && !mini_pacman_neighbors(point: [x, y], maze: maze).empty?)
          maze[y][x] = rng.rand < 0.5 ? '#' : ' ' if !ring && width <= 6 && height <= 6
        end
      end
      spaces = (0...height).flat_map { |y| (0...width).filter_map { |x| [x, y] if maze[y][x] == ' ' } }
      corners = [[1, 1], [width - 2, 1], [1, height - 2], [width - 2, height - 2]]
      start = [1, height - 2]
      homes = [[width - 2, 1], [width - 2, height - 2], [1, 1]].take(opts[:ghost_count] || (width < 8 ? 1 : 3))
      { maze: maze, pacman: start, direction: :right, buffered: nil, pellets: spaces - corners - [start], power: corners,
        ghosts: homes.map.with_index { |point, index| { position: point, home: point.dup, color: %w[R M C][index], delay: 3 + (index * 4) } },
        frightened: 0, score: opts[:score] || 0, level: opts[:level] || 1, started: false, tick: 0 }
    end

    private_class_method def self.mini_pacman_snapshot(opts = {})
      state = opts[:state]
      board = state[:maze].map(&:dup)
      state[:pellets].each { |x, y| board[y][x] = '.' }
      state[:power].each { |x, y| board[y][x] = '*' }
      state[:ghosts].each do |ghost|
        x, y = ghost[:position]
        board[y][x] = state[:frightened].positive? ? 'F' : ghost[:color]
      end
      x, y = state[:pacman]
      board[y][x] = { right: '>', left: '<', up: '^', down: 'v' }.fetch(state[:direction])
      board[y][x] = 'O' if state[:tick] % 3 == 2
      board[y][x] = 'w' if opts[:event] == :game_over
      board.map! { |row| row.tr('#', 'w') } if opts[:event] == :level_complete
      # Coordinates and maze rows are replaced, never mutated. Share these
      # immutable leaves instead of serializing the whole maze on every tick.
      snapshot = state.merge(pellets: state[:pellets].dup, power: state[:power].dup, ghosts: state[:ghosts].map(&:dup))
      mini_emit(frames: opts[:frames], board: board, state: snapshot, event: opts[:event] || :ready)
    end

    private_class_method def self.mini_pacman_neighbors(opts = {})
      x, y = opts[:point]
      maze = opts[:maze]
      { right: [x + 1, y], left: [x - 1, y], up: [x, y - 1], down: [x, y + 1] }.select do |_, (nx, ny)|
        ny.between?(0, maze.length - 1) && nx.between?(0, maze.first.length - 1) && maze[ny][nx] != '#'
      end
    end

    private_class_method def self.mini_pacman_move(opts = {})
      state = opts[:state]
      keys = opts[:keys] || []
      turn = keys.reverse.find { |key| %i[up down left right].include?(key) }
      state[:buffered] = turn if turn
      state[:started] ||= !turn.nil?
      return :ready unless state[:started]

      state[:tick] += 1
      state[:frightened] -= 1 if state[:frightened].positive?
      return :play unless ((state[:tick] - 1) % 3).zero?

      neighbors = mini_pacman_neighbors(point: state[:pacman], maze: state[:maze])
      state[:direction] = state[:buffered] if neighbors.key?(state[:buffered])
      state[:pacman] = neighbors.fetch(state[:direction], state[:pacman])
      state[:score] += 10 if state[:pellets].delete(state[:pacman])
      event = :play
      if state[:power].delete(state[:pacman])
        state[:score] += 50
        state[:frightened] = 70
        event = :power
      end
      collision = mini_pacman_contact(state: state)
      return collision if collision == :game_over

      event = collision || event
      mini_pacman_ghosts(state: state, rng: opts[:rng] || Random.new(MINI_SEED))
      collision = mini_pacman_contact(state: state)
      return collision if collision == :game_over
      return :level_complete if state[:pellets].empty? && state[:power].empty?

      collision || event
    end

    private_class_method def self.mini_pacman_contact(opts = {})
      state = opts[:state]
      event = nil
      state[:ghosts].each do |ghost|
        next if ghost[:returning]
        next unless ghost[:position] == state[:pacman]
        return :game_over if state[:frightened].zero?

        state[:score] += 200
        ghost[:position] = ghost[:home].dup
        ghost[:delay] = 12
        ghost[:returning] = true
        event = :ghost_eaten
      end
      event
    end

    # Breadth-first routing cannot get trapped behind a wall or circle a pellet.
    private_class_method def self.mini_pacman_route(opts = {})
      queue = [[opts[:point], nil]]
      seen = { opts[:point] => true }
      cursor = 0
      while cursor < queue.length
        point, first = queue[cursor]
        cursor += 1
        return first if first && opts[:targets].include?(point)

        mini_pacman_neighbors(point: point, maze: opts[:maze]).to_a.shuffle(random: opts[:rng]).each do |key, neighbor|
          next if seen[neighbor]

          seen[neighbor] = true
          queue << [neighbor, first || key]
        end
      end
      nil
    end

    private_class_method def self.mini_pacman_ghosts(opts = {})
      state, rng = opts.values_at(:state, :rng)
      state[:ghosts].each do |ghost|
        if ghost[:delay].positive?
          ghost[:delay] -= 1
          next
        end
        ghost[:returning] = false
        next unless ((state[:tick] - 1) % 6).zero?

        neighbors = mini_pacman_neighbors(point: ghost[:position], maze: state[:maze])
        key = if state[:frightened].positive?
                neighbors.keys.shuffle(random: rng).max_by do |direction|
                  point = neighbors[direction]
                  (point[0] - state[:pacman][0]).abs + (point[1] - state[:pacman][1]).abs
                end
              else
                mini_pacman_route(point: ghost[:position], targets: [state[:pacman]], maze: state[:maze], rng: rng)
              end
        ghost[:position] = neighbors.fetch(key, ghost[:position])
      end
    end

    private_class_method def self.mini_simulate_pacman(opts = {})
      # Maze topology takes priority over actor detail, including the normal
      # eight-cell console pane. Enlarged tiles reduced it to a 5x5 ring.
      round = { width: opts[:width], height: opts[:height],
                ghost_count: opts[:width] < 12 ? 1 : 3, rng: opts[:rng] }
      state = mini_pacman_round(round)
      frames = opts[:frames]
      event = :ready
      while frames.length < MINI_FRAME_COUNT
        mini_pacman_snapshot(frames: frames, state: state, event: event)
        keys = if opts[:player]
                 opts[:player].controls
               elsif (state[:tick] % 3).zero?
                 [mini_pacman_route(point: state[:pacman], targets: state[:power] + state[:pellets], maze: state[:maze], rng: opts[:rng])]
               end
        event = mini_pacman_move(state: state, keys: keys, rng: opts[:rng])
        next unless %i[game_over level_complete].include?(event)

        5.times { mini_pacman_snapshot(frames: frames, state: state, event: event) }
        opts[:player]&.controls
        level = event == :level_complete ? state[:level] + 1 : 1
        score = event == :level_complete ? state[:score] : 0
        state = mini_pacman_round(round.merge(level: level, score: score))
        event = :ready
      end
    end

    private_class_method def self.mini_frogger_round(opts = {})
      width, height = opts.values_at(:width, :height)
      rng = opts[:rng]
      level = opts[:level] || 1
      bank = height >= 5 ? height / 2 : -1
      lanes = (1...(height - 1)).filter_map do |y|
        next if y == bank

        water = y < height / 2
        { y: y, water: water, offset: rng.rand * width, period: width.to_f,
          length: water ? width * 0.65 : [width * 0.22, 1.0].max,
          speed: (y.even? ? -1 : 1) * [0.06 + (rng.rand * 0.04) + (level * 0.015), 0.2].min }
      end
      { frog: [width / 2.0, height - 1], lanes: lanes, goals: width < 8 ? [width / 2] : [1, width / 2, width - 2],
        filled: [], level: level, score: opts[:score] || 0, tick: 0, started: false, explosion: 0 }
    end

    private_class_method def self.mini_frogger_contact(opts = {})
      state = opts[:state]
      x, y = state[:frog]
      return :game_over unless x.between?(0, opts[:width] - 1)

      if y.zero?
        goal = state[:goals].find { |slot| (slot - x).abs <= 0.55 && !state[:filled].include?(slot) }
        return :game_over unless goal

        state[:filled] << goal
        state[:score] += 100
        state[:frog] = [opts[:width] / 2.0, opts[:height] - 1]
        return state[:filled].length == state[:goals].length ? :level_complete : :goal
      end
      lane = state[:lanes].find { |row| row[:y] == y }
      return :play unless lane

      occupied = ((x - lane[:offset]) % lane[:period]) < lane[:length]
      occupied == lane[:water] ? :play : :game_over
    end

    private_class_method def self.mini_frogger_move(opts = {})
      state = opts[:state]
      keys = (opts[:keys] || []).select { |key| %i[left right up down].include?(key) }
      state[:started] ||= !keys.empty?
      return :ready unless state[:started]

      state[:tick] += 1
      keys.each do |key|
        dx, dy = { left: [-1, 0], right: [1, 0], up: [0, -1], down: [0, 1] }.fetch(key)
        state[:frog] = [(state[:frog][0] + dx).clamp(0, opts[:width] - 1), (state[:frog][1] + dy).clamp(0, opts[:height] - 1)]
        event = mini_frogger_contact(opts)
        return event unless event == :play
      end
      # Check the landing before carrying: a hop into open water cannot be
      # rescued by a log that arrives later in the same simulation tick.
      event = mini_frogger_contact(opts)
      return event unless event == :play

      state[:lanes].each do |lane|
        state[:frog][0] += lane[:speed] if lane[:water] && state[:frog][1] == lane[:y]
        lane[:offset] = (lane[:offset] + lane[:speed]) % lane[:period]
      end
      mini_frogger_contact(opts)
    end

    private_class_method def self.mini_frogger_snapshot(opts = {})
      state, width, height = opts.values_at(:state, :width, :height)
      board = Array.new(height) { ' ' * width }
      state[:goals].each { |x| board[0][x] = state[:filled].include?(x) ? 'H' : 'U' }
      state[:lanes].each do |lane|
        width.times do |x|
          occupied = ((x - lane[:offset]) % lane[:period]) < lane[:length]
          board[lane[:y]][x] = if lane[:water]
                                 occupied ? '=' : '~'
                               else
                                 occupied ? 'T' : '.'
                               end
        end
      end
      x, y = state[:frog]
      board[y][x.round.clamp(0, width - 1)] = state[:explosion].positive? ? '+' : 'H'
      mini_emit(frames: opts[:frames], board: board, state: Marshal.load(Marshal.dump(state)), event: opts[:event])
    end

    private_class_method def self.mini_frogger_demo(opts = {})
      state = opts[:state]
      return [] unless (state[:tick] % 3).zero?

      goal = (state[:goals] - state[:filled]).min_by { |x| (state[:frog][0] - x).abs }
      preferred = state[:frog][0] < goal ? :right : :left
      candidates = state[:frog][1] == 1 && (state[:frog][0] - goal).abs > 0.55 ? [preferred, :up] : [:up, preferred]
      candidates.each do |key|
        copy = Marshal.load(Marshal.dump(state))
        result = mini_frogger_move(opts.merge(state: copy, keys: [key]))
        return [key] unless result == :game_over
      end
      []
    end

    private_class_method def self.mini_simulate_frogger(opts = {})
      state = mini_frogger_round(opts)
      event = :ready
      while opts[:frames].length < MINI_FRAME_COUNT
        mini_frogger_snapshot(opts.merge(state: state, event: event))
        keys = opts[:player]&.controls
        if state[:explosion].positive?
          state[:explosion] -= 1
          if state[:explosion].zero?
            state[:frog] = [opts[:width] / 2.0, opts[:height] - 1]
            state[:started] = false
            event = :ready
          end
          next
        end
        keys = mini_frogger_demo(opts.merge(state: state)) unless opts[:player]
        event = mini_frogger_move(opts.merge(state: state, keys: keys))
        state[:explosion] = 8 if event == :game_over
        state = mini_frogger_round(opts.merge(level: state[:level] + 1, score: state[:score])) if event == :level_complete
      end
    end

    private_class_method def self.mini_galaga_round(opts = {})
      width, height = opts.values_at(:width, :height)
      enemies = (1...(width - 1)).step(2).flat_map do |x|
        [0, 1].map { |y| { x: x.to_f, y: y.to_f, home: [x, y], diving: false, phase: 0 } }
      end
      { ship: [width / 2.0, height - 1.0], enemies: enemies, shots: [], hostile: [],
        tick: 0, started: false, explosion: 0, cooldown: 0, level: opts[:level] || 1, score: opts[:score] || 0 }
    end

    private_class_method def self.mini_galaga_move(opts = {})
      state, width, height, rng = opts.values_at(:state, :width, :height, :rng)
      keys = opts[:keys] || []
      state[:started] ||= !keys.empty?
      return :ready unless state[:started]

      state[:tick] += 1
      state[:cooldown] -= 1 if state[:cooldown].positive?
      keys.each do |key|
        dx, dy = { left: [-0.75, 0], right: [0.75, 0], up: [0, -0.6], down: [0, 0.6] }.fetch(key, [0, 0])
        state[:ship] = [(state[:ship][0] + dx).clamp(0, width - 1), (state[:ship][1] + dy).clamp(height / 2.0, height - 1)]
        next unless key == ' ' && state[:cooldown].zero?

        state[:shots] << [state[:ship][0], state[:ship][1] - 0.5]
        state[:cooldown] = 3
      end
      speed = [0.08 + (state[:level] * 0.02), 0.22].min
      state[:enemies].each do |enemy|
        if enemy[:diving]
          enemy[:phase] += 0.12
          enemy[:x] = (enemy[:x] + (Math.sin(enemy[:phase]) * 0.18)).clamp(0, width - 1)
          enemy[:y] += speed
          enemy[:diving] = false if enemy[:y] > height
        else
          enemy[:x] = (enemy[:home][0] + (Math.sin(state[:tick] * 0.035) * 0.6)).clamp(0, width - 1)
          enemy[:y] = enemy[:home][1].to_f
        end
      end
      if (state[:tick] % 24).zero? && !state[:enemies].empty?
        enemy = state[:enemies].sample(random: rng)
        enemy[:diving] = true
        enemy[:phase] = 0
      end
      if (state[:tick] % 16).zero? && !state[:enemies].empty?
        enemy = state[:enemies].sample(random: rng)
        dx = (state[:ship][0] - enemy[:x]) * 0.025
        state[:hostile] << [enemy[:x], enemy[:y], dx.clamp(-0.12, 0.12)]
      end
      event = :play
      state[:shots].delete_if do |shot|
        previous = shot[1]
        shot[1] -= 0.65
        enemy = state[:enemies].find { |target| (target[:x] - shot[0]).abs < 0.65 && target[:y].between?(shot[1] - 0.4, previous + 0.4) }
        if enemy
          state[:enemies].delete(enemy)
          state[:score] += enemy[:diving] ? 100 : 50
          event = :hit
        end
        enemy || shot[1].negative?
      end
      state[:hostile].each do |shot|
        shot[0] += shot[2]
        shot[1] += 0.18 + speed
      end
      hit = state[:hostile].any? { |x, y, _| (x - state[:ship][0]).abs < 0.55 && (y - state[:ship][1]).abs < 0.6 }
      hit ||= state[:enemies].any? { |enemy| (enemy[:x] - state[:ship][0]).abs < 0.65 && (enemy[:y] - state[:ship][1]).abs < 0.65 }
      state[:hostile].reject! { |x, y, _| y >= height || x.negative? || x >= width }
      return :game_over if hit
      return :wave_complete if state[:enemies].empty?

      event
    end

    private_class_method def self.mini_galaga_snapshot(opts = {})
      state, width, height = opts.values_at(:state, :width, :height)
      board = Array.new(height) { ' ' * width }
      state[:enemies].each do |enemy|
        x, y = enemy.values_at(:x, :y).map(&:round)
        board[y][x] = enemy[:diving] ? 'B' : 'E' if x.between?(0, width - 1) && y.between?(0, height - 1)
      end
      (state[:shots].map { |x, y| [x, y, '!'] } + state[:hostile].map { |x, y, _| [x, y, 'i'] }).each do |x, y, pixel|
        board[y.round][x.round] = pixel if x.round.between?(0, width - 1) && y.round.between?(0, height - 1)
      end
      x, y = state[:ship].map(&:round)
      if state[:explosion].positive?
        board[y][x] = '+'
      else
        # A filled five-dot delta: narrow nose, solid spine and swept wings.
        # Painting alone uses the existing 2x4 raster; physics stays in cells.
        nose_x = (state[:ship][0] * 2).round.clamp(2, (width * 2) - 3)
        base_y = ((state[:ship][1] * 4).round + 3).clamp(4, (height * 4) - 1)
        [0, 1, 1, 2, 2].each_with_index do |radius, dy|
          (-radius..radius).each do |dx|
            mini_dot(board: board, x: nose_x + dx, y: base_y - 4 + dy, color: 0)
          end
        end
      end
      if state[:explosion].positive?
        radius = (8 - state[:explosion]) / 2
        [[radius, 0], [-radius, 0], [0, radius], [0, -radius]].each do |dx, dy|
          board[y + dy][x + dx] = 'i' if (x + dx).between?(0, width - 1) && (y + dy).between?(0, height - 1)
        end
      end
      mini_emit(frames: opts[:frames], board: board, state: Marshal.load(Marshal.dump(state)), event: opts[:event])
    end

    private_class_method def self.mini_simulate_galaga(opts = {})
      state = mini_galaga_round(opts)
      event = :ready
      while opts[:frames].length < MINI_FRAME_COUNT
        mini_galaga_snapshot(opts.merge(state: state, event: event))
        keys = opts[:player]&.controls
        if state[:explosion].positive?
          state[:explosion] -= 1
          if state[:explosion].zero?
            state = mini_galaga_round(opts)
            event = :ready
          end
          next
        end
        unless opts[:player]
          target = state[:enemies].min_by { |enemy| (enemy[:x] - state[:ship][0]).abs }
          dx = target ? target[:x] - state[:ship][0] : 0
          keys = [' ']
          keys << (dx.positive? ? :right : :left) if dx.abs > 0.5
        end
        event = mini_galaga_move(opts.merge(state: state, keys: keys))
        state[:explosion] = 8 if event == :game_over
        state = mini_galaga_round(opts.merge(level: state[:level] + 1, score: state[:score])) if event == :wave_complete
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

    # Braille provides twice the vertical samples of quadrants and much finer
    # ink. Preserve the full canvas and physics coordinates, not a shrunken board.
    private_class_method def self.mini_dot(opts = {})
      board = opts[:board]
      x = opts[:x] % (board.first.length * 2)
      y = opts[:y] % (board.length * 4)
      color = opts[:color]
      prior = board[y / 4][x / 2].ord - 4096
      mask = prior >= 0 && prior / 256 == color ? prior % 256 : 0
      bit = [[0, 1, 2, 6], [3, 4, 5, 7]][x % 2][y % 4]
      board[y / 4][x / 2] = (4096 + (color * 256) + (mask | (1 << bit))).chr(Encoding::UTF_8)
    end

    private_class_method def self.mini_simulate_asteroids(opts = {})
      frames, width, height, rng = opts.values_at(:frames, :width, :height, :rng)
      ship = [width / 2.0, height / 2.0, rng.rand * Math::PI * 2]
      velocity = [0.0, 0.0]
      rocks = []
      shots = []
      sparks = []
      explosion = 0
      invulnerable = 0
      serial = 0
      tick = 0
      while frames.length < MINI_FRAME_COUNT
        event = :play
        if explosion.positive?
          explosion -= 1
          if explosion.zero?
            invulnerable = 30
            event = :recover
          end
        elsif invulnerable.positive?
          invulnerable -= 1
        end
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
        keys = [] if explosion.positive?
        turn = keys.sum { |key| { left: -Math::PI / 4, right: Math::PI / 4 }.fetch(key, 0) } if keys
        ship[2] = (ship[2] + turn) % (Math::PI * 2)
        power = tick % 80 < 24 ? 1 : 0
        power = keys.sum { |key| { up: 1, down: -1 }.fetch(key, 0) }.clamp(-1, 1) if keys
        thrust = !power.zero?
        [Math.cos(ship[2]), Math.sin(ship[2])].each_with_index do |direction, axis|
          acceleration = keys ? 0.08 : 0.006
          velocity[axis] = ((velocity[axis] * 0.99) + (direction * acceleration * power)).clamp(-0.15, 0.15)
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
        # Decorative autopilot retains its existing physics. Player impacts use
        # the same wrapped world as shots, with a compact hull collision radius.
        if opts[:player] && explosion.zero? && invulnerable.zero? && rocks.any? do |rock|
             dx = mini_delta(from: ship[0], to: rock[0], span: width)
             dy = mini_delta(from: ship[1], to: rock[1], span: height)
             (dx * dx) + (dy * dy) <= (rock[4] + 0.55)**2
           end
          explosion = 12
          velocity = [0.0, 0.0]
          thrust = false
          event = :crash
        end
        mini_asteroids_snapshot(frames: frames, width: width, height: height, ship: ship, thrust: thrust,
                                rocks: rocks, shots: shots, sparks: sparks, event: event, explosion: explosion, invulnerable: invulnerable)
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
          mini_dot(board: board, x: ((x + dx) * 2).round, y: ((y + dy) * 4).round, color: 3)
        end
      end
      sparks.each do |x, y, life|
        2.times do |index|
          angle = index * Math::PI
          radius = (8 - life) * 0.12
          mini_dot(board: board, x: ((x + (Math.cos(angle) * radius)) * 2).round, y: ((y + (Math.sin(angle) * radius)) * 4).round, color: 3)
        end
      end
      shots.each { |x, y,| mini_dot(board: board, x: (x * 2).round, y: (y * 4).round, color: 2) }
      if opts[:thrust] && opts[:explosion].to_i.zero?
        # A black subpixel gap separates exhaust from hull: a terminal cell has
        # only two colors, so cyan/red/black in one quadrant glyph loses the red.
        mini_dot(board: board, x: ((ship[0] * 2) - (Math.cos(ship[2]) * 5)).round,
                 y: ((ship[1] * 4) - (Math.sin(ship[2]) * 8)).round, color: 5)
      end
      if opts[:explosion].to_i.positive?
        life = opts[:explosion]
        8.times do |index|
          angle = index * Math::PI / 4
          radius = 0.3 + ((12 - life) * 0.13)
          mini_dot(board: board, x: ((ship[0] + (Math.cos(angle) * radius)) * 2).round,
                   y: ((ship[1] + (Math.sin(angle) * radius)) * 4).round, color: life > 8 ? 2 : 5)
        end
      else
        MINI_SHIP[(ship[2] * 4 / Math::PI).round % 8].each do |dx, dy|
          mini_dot(board: board, x: (ship[0] * 2).round + dx, y: (ship[1] * 4).round + dy, color: 0)
        end
      end
      mini_emit(frames: opts[:frames], board: board, event: opts[:event],
                state: { ship: ship.dup, thrust: opts[:thrust], rocks: rocks.map(&:dup), shots: shots.map(&:dup),
                         explosion: opts[:explosion].to_i, invulnerable: opts[:invulnerable].to_i })
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

    private_class_method def self.mini_pacman(opts = {})
      rows = opts[:rows]
      replay = mini_replay(name: :pacman, width: opts[:width], height: opts[:height], seed: MINI_SEED)
      replay[opts[:phase] + 6][:rows].drop(1).each_with_index do |row, y|
        rows[y + 1] = row.chars.map { |pixel| pixel.ord > 127 ? '@' : pixel.tr('RMCF><^v*Ow', 'GGGGCCCCoC!') }.join
      end
    end

    # Retained for existing direct API callers, never offered by mini_names.
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
          name: 'optional - falling_blocks, snake, pacman, asteroids, galaga or frogger; legacy pong accepted; defaults to falling_blocks',
          frame: 'optional - integer frame index, defaults to zero and wraps at 60',
          width: 'optional - columns clamped to zero through 16; defaults to 16',
          height: 'optional - rows clamped to zero through 16; defaults to 16',
          branding: 'optional - include the legacy wordmark, defaults to true; false reclaims its row'
        )

        # Return fresh Unicode block cells: { glyph:, foreground:, background: }.
        # Colors are standard terminal names; blocks may use colored backgrounds.
        # No ANSI or IO. Other games retain black backgrounds.
        # 1800 frames; mini_frame_seconds is 0.05 for Asteroids/legacy Pong, 0.1 otherwise.
        # Caller samples mini_names once per session. No timers or animation threads.
        # Seeded gameplay, bounded six-replay cache; white hold/wipe marks resets.
        # Square refers to terminal cells, not physical pixels. Caller owns borders.
        #{self}.mini_cells(
          name: 'optional - falling_blocks, snake, pacman, asteroids, galaga or frogger; legacy pong accepted; defaults to falling_blocks',
          frame: 'optional - integer frame index, defaults to zero and wraps at 1800',
          width: 'optional - columns clamped to 0..64 for blocks/Pac-Man/Galaga/Frogger, 0..16 otherwise; defaults to 16',
          height: 'optional - rows clamped to 0..64 for blocks/Pac-Man/Galaga/Frogger, 0..16 otherwise; defaults to 16',
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
