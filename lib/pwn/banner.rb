# frozen_string_literal: true

module PWN
  # Static banners and pure, PWN-branded retro ASCII loops: falling_blocks,
  # snake, and pong. mini_frame returns fresh rows on a borderless canvas;
  # use equal width and height (5..16) for complete square artwork. Dimensions
  # clamp to 0..16, with smaller panes degrading to a wordmark. The caller
  # samples mini_names once per session and advances the explicit frame index
  # every MINI_FRAME_SECONDS (0.1), wrapping at MINI_FRAME_COUNT (60).
  # These are decorative animations, not interactive games or telemetry.
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
    MINI_FRAME_COUNT = 60

    # Supported Method Parameters::
    # Return fresh ASCII rows for decorative retro loops, not interactive games.
    # Use equal width and height for a square; 5..16 retains the complete artwork.
    # Smaller panes degrade to a wordmark. Caller owns randomness, clock and IO.
    # PWN::Banner.mini_frame(
    #   name: 'optional - falling_blocks, snake, or pong; defaults to falling_blocks',
    #   frame: 'optional - integer frame index, defaults to zero and wraps at 60',
    #   width: 'optional - output columns clamped to zero through 16, defaults to 16',
    #   height: 'optional - output rows clamped to zero through 16, defaults to 16'
    # )

    public_class_method def self.mini_frame(opts = {})
      name = (opts[:name] || :falling_blocks).to_s
      raise ArgumentError, "Unknown mini-banner: #{name}" unless mini_names.map(&:to_s).include?(name)

      phase = (opts[:frame] || 0).to_i % MINI_FRAME_COUNT
      width = (opts[:width] || MINI_WIDTH).to_i.clamp(0, MINI_WIDTH)
      height = (opts[:height] || MINI_HEIGHT).to_i.clamp(0, MINI_HEIGHT)
      return [] if width.zero? || height.zero?

      rows = Array.new(height) { ' ' * width }
      rows[0] = 'PWN'[0, width].center(width)
      return rows if width < 5 || height < 5

      send("mini_#{name}", rows: rows, phase: phase, width: width, height: height)
      rows
    end

    # Supported Method Parameters::
    # List animation names; callers may sample once and retain the session choice.
    # PWN::Banner.mini_names

    public_class_method def self.mini_names
      %i[falling_blocks snake pong]
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
      head = opts[:phase] * path.length / MINI_FRAME_COUNT
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

        # Return fresh ASCII rows; caller owns timing, theme, and terminal drawing.
        # Decorative retro loops, not interactive games or progress/telemetry.
        # Advance every MINI_FRAME_SECONDS (0.1 seconds); MINI_FRAME_COUNT is 60.
        # Pass equal width and height for a square; complete artwork fits 5..16.
        # No border is included. Smaller panes show only a clipped PWN wordmark.
        #{self}.mini_frame(
          name: 'optional - falling_blocks, snake, or pong; defaults to falling_blocks',
          frame: 'optional - integer frame index, defaults to zero and wraps at 60',
          width: 'optional - columns clamped to zero through 16; defaults to 16',
          height: 'optional - rows clamped to zero through 16; defaults to 16'
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
