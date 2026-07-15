# frozen_string_literal: true

require 'rbconfig'
require 'English'
require 'shellwords'

module PWN
  # PWN::Setup — post-install "doctor" and capability provisioner.
  #
  # PWN ships as a **single gem** whose runtime is 100 % `autoload`ed
  # (`lib/pwn.rb`) — a plugin whose native gem or OS binary is missing
  # costs nothing until you touch that constant.  `PWN::Setup` is the
  # piece that grows a bare `gem install pwn` into a fully-armed host
  # **after** the gem is installed, instead of **before** via a chain
  # of bash scripts that assume `/opt/pwn`, `rvmsudo`, `screen`, and
  # MacPorts.
  #
  # It is the Ruby-native, versioned-with-the-gem replacement for the
  # `case $os` blocks previously buried in `install.sh` and
  # `packer/provisioners/pwn.sh`.
  #
  #   pwn setup                       # doctor (read-only)
  #   pwn setup --check               # same
  #   pwn setup --deps                # install OS headers for EVERY native gem
  #   pwn setup --profile web         # install just what TransparentBrowser/Burp need
  #   pwn setup --profile sdr --yes   # non-interactive
  #   pwn setup --list-profiles
  #
  # Also exposed as `pwn_setup` (driver) and `pwn --setup[=PROFILE]`.
  module Setup
    # ------------------------------------------------------------------
    # DATA — the single source of truth for "what OS packages does this
    # capability need". Straight port of packer/provisioners/pwn.sh, but
    # now it is **data**, versioned with the gem, testable, and identical
    # on every install path (gem, git checkout, docker, packer, vagrant).
    # ------------------------------------------------------------------

    # Native-extension Ruby gems → OS headers/libs required to compile them,
    # per package manager, plus the PWN:: constants they unlock.
    NATIVE_GEMS = {
      'pg' => {
        apt: %w[postgresql-server-dev-all], dnf: %w[postgresql-devel],
        pacman: %w[postgresql-libs], brew: %w[postgresql], port: %w[postgresql16-server],
        plugins: %w[PWN::Plugins::DAOPostgres]
      },
      'sqlite3' => {
        apt: %w[libsqlite3-dev], dnf: %w[sqlite-devel],
        pacman: %w[sqlite], brew: %w[sqlite], port: %w[sqlite3],
        plugins: %w[PWN::Plugins::DAOSqlite3]
      },
      'pcaprub' => {
        apt: %w[libpcap-dev], dnf: %w[libpcap-devel],
        pacman: %w[libpcap], brew: %w[libpcap], port: %w[libpcap],
        plugins: %w[PWN::Plugins::Packet extro_packet]
      },
      'rmagick' => {
        apt: %w[imagemagick libmagickwand-dev], dnf: %w[ImageMagick-devel],
        pacman: %w[imagemagick], brew: %w[imagemagick], port: %w[imagemagick],
        plugins: %w[PWN::Plugins::OCR PWN::Reports]
      },
      'rtesseract' => {
        apt: %w[tesseract-ocr tesseract-ocr-all], dnf: %w[tesseract],
        pacman: %w[tesseract tesseract-data-eng], brew: %w[tesseract], port: %w[tesseract],
        plugins: %w[PWN::Plugins::OCR extro_vision]
      },
      'ruby-audio' => {
        apt: %w[libsndfile1-dev], dnf: %w[libsndfile-devel],
        pacman: %w[libsndfile], brew: %w[libsndfile], port: %w[libsndfile],
        plugins: %w[PWN::Plugins::Voice PWN::SDR extro_voice]
      },
      'curses' => {
        apt: %w[libncurses-dev], dnf: %w[ncurses-devel],
        pacman: %w[ncurses], brew: %w[ncurses], port: %w[ncurses],
        plugins: %w[PWN::Plugins::REPL]
      },
      'libusb' => {
        apt: %w[libusb-1.0-0-dev], dnf: %w[libusbx-devel],
        pacman: %w[libusb], brew: %w[libusb], port: %w[libusb],
        plugins: %w[PWN::SDR PWN::Plugins::BusPirate]
      },
      'ffi' => {
        apt: %w[libffi-dev], dnf: %w[libffi-devel],
        pacman: %w[libffi], brew: %w[libffi], port: %w[libffi],
        plugins: %w[PWN::FFI]
      },
      'nokogiri' => {
        apt: %w[libxml2-dev libxslt1-dev], dnf: %w[libxml2-devel libxslt-devel],
        pacman: %w[libxml2 libxslt], brew: %w[libxml2], port: %w[libxml2 libxslt],
        plugins: %w[PWN::Plugins::TransparentBrowser PWN::WWW]
      },
      'oily_png' => {
        apt: %w[build-essential], dnf: %w[gcc make],
        pacman: %w[base-devel], brew: %w[gcc], port: %w[gcc12],
        plugins: %w[PWN::Plugins::ScannableCodes]
      },
      'eventmachine' => {
        apt: %w[libssl-dev], dnf: %w[openssl-devel],
        pacman: %w[openssl], brew: %w[openssl], port: %w[openssl],
        plugins: %w[PWN::Plugins::Sock PWN::Plugins::IRC]
      },
      'gruff' => {
        apt: %w[imagemagick libmagickwand-dev], dnf: %w[ImageMagick-devel],
        pacman: %w[imagemagick], brew: %w[imagemagick], port: %w[imagemagick],
        plugins: %w[PWN::Reports]
      },
      # Not a native extension, but gated by required_ruby_version >= 4.0 on
      # rubygems.org — so it cannot be a hard runtime dependency of pwn while
      # pwn.gemspec advertises `>= 3.3`. Managed here instead so
      # `gem install pwn` succeeds on distro rubies (3.3/3.4) and `pwn setup`
      # installs it post-hoc where possible. See install-matrix.yml.
      'meshtastic' => {
        apt: %w[], dnf: %w[], pacman: %w[], brew: %w[], port: %w[],
        min_ruby: '4.0.0',
        plugins: %w[PWN::Plugins::REPL#pwn-mesh]
      }
    }.freeze

    # External binaries PWN wraps → OS packages that provide them.
    # (Extrospection.probe_toolchain already knows how to *detect* these;
    #  this table knows how to *install* them.)
    TOOLCHAIN = {
      'nmap' => {
        apt: %w[nmap], dnf: %w[nmap], pacman: %w[nmap], brew: %w[nmap], port: %w[nmap],
        plugins: %w[PWN::Plugins::NmapIt]
      },
      'chromium' => {
        apt: %w[chromium], dnf: %w[chromium], pacman: %w[chromium], brew: %w[chromium], port: %w[chromium],
        plugins: %w[PWN::Plugins::TransparentBrowser extro_verify extro_watch]
      },
      'geckodriver' => {
        apt: %w[firefox-esr], dnf: %w[firefox], pacman: %w[geckodriver], brew: %w[geckodriver], port: %w[geckodriver],
        plugins: %w[PWN::Plugins::TransparentBrowser]
      },
      'msfconsole' => {
        apt: %w[metasploit-framework], dnf: %w[metasploit-framework], pacman: %w[metasploit],
        brew: %w[metasploit], port: %w[],
        plugins: %w[PWN::Plugins::Metasploit]
      },
      'burpsuite' => {
        apt: %w[burpsuite], dnf: %w[], pacman: %w[burpsuite], brew: %w[burp-suite], port: %w[],
        plugins: %w[PWN::Plugins::BurpSuite]
      },
      'zaproxy' => {
        apt: %w[zaproxy], dnf: %w[], pacman: %w[zaproxy], brew: %w[zap], port: %w[],
        plugins: %w[PWN::Plugins::Zaproxy]
      },
      'sqlmap' => {
        apt: %w[sqlmap], dnf: %w[sqlmap], pacman: %w[sqlmap], brew: %w[sqlmap], port: %w[],
        plugins: %w[PWN::Plugins::Fuzz]
      },
      'tor' => {
        apt: %w[tor], dnf: %w[tor], pacman: %w[tor], brew: %w[tor], port: %w[tor],
        plugins: %w[PWN::Plugins::Tor]
      },
      'tshark' => {
        apt: %w[tshark], dnf: %w[wireshark-cli], pacman: %w[wireshark-cli],
        brew: %w[wireshark], port: %w[wireshark],
        plugins: %w[PWN::Plugins::Packet extro_packet]
      },
      'tcpdump' => {
        apt: %w[tcpdump], dnf: %w[tcpdump], pacman: %w[tcpdump], brew: %w[tcpdump], port: %w[tcpdump],
        plugins: %w[PWN::Plugins::Packet extro_packet]
      },
      'tesseract' => {
        apt: %w[tesseract-ocr], dnf: %w[tesseract], pacman: %w[tesseract],
        brew: %w[tesseract], port: %w[tesseract],
        plugins: %w[PWN::Plugins::OCR extro_vision]
      },
      'zbarimg' => {
        apt: %w[zbar-tools], dnf: %w[zbar], pacman: %w[zbar], brew: %w[zbar], port: %w[zbar],
        plugins: %w[PWN::Plugins::ScannableCodes extro_vision]
      },
      'espeak-ng' => {
        apt: %w[espeak-ng], dnf: %w[espeak-ng], pacman: %w[espeak-ng],
        brew: %w[espeak-ng], port: %w[espeak-ng],
        plugins: %w[PWN::Plugins::Voice extro_voice]
      },
      'sox' => {
        apt: %w[sox], dnf: %w[sox], pacman: %w[sox], brew: %w[sox], port: %w[sox],
        plugins: %w[PWN::Plugins::Voice PWN::SDR]
      },
      'gqrx' => {
        apt: %w[gqrx-sdr], dnf: %w[gqrx], pacman: %w[gqrx], brew: %w[gqrx], port: %w[gqrx],
        plugins: %w[PWN::SDR extro_rf_tune]
      },
      'rtl_sdr' => {
        apt: %w[rtl-sdr], dnf: %w[rtl-sdr], pacman: %w[rtl-sdr], brew: %w[librtlsdr], port: %w[rtl-sdr],
        plugins: %w[PWN::SDR PWN::FFI::RTLSdr]
      },
      'hackrf_info' => {
        apt: %w[hackrf], dnf: %w[hackrf], pacman: %w[hackrf], brew: %w[hackrf], port: %w[hackrf],
        plugins: %w[PWN::SDR PWN::FFI::HackRF]
      },
      'SoapySDRUtil' => {
        apt: %w[soapysdr-tools], dnf: %w[SoapySDR], pacman: %w[soapysdr],
        brew: %w[soapysdr], port: %w[SoapySDR],
        plugins: %w[PWN::SDR PWN::FFI::SoapySDR]
      },
      'multimon-ng' => {
        apt: %w[multimon-ng], dnf: %w[multimon-ng], pacman: %w[multimon-ng],
        brew: %w[multimon-ng], port: %w[],
        plugins: %w[PWN::SDR::Decoder]
      },
      'dot' => {
        apt: %w[graphviz], dnf: %w[graphviz], pacman: %w[graphviz],
        brew: %w[graphviz], port: %w[graphviz],
        plugins: %w[documentation/diagrams]
      },
      'adb' => {
        apt: %w[adb], dnf: %w[android-tools], pacman: %w[android-tools],
        brew: %w[android-platform-tools], port: %w[],
        plugins: %w[PWN::Plugins::Android]
      },
      'baresip' => {
        apt: %w[baresip], dnf: %w[baresip], pacman: %w[baresip], brew: %w[baresip], port: %w[],
        plugins: %w[PWN::Plugins::BareSIP extro_telecomm]
      },
      'whois' => {
        apt: %w[whois], dnf: %w[whois], pacman: %w[whois], brew: %w[whois], port: %w[whois],
        plugins: %w[extro_osint]
      },
      'jq' => {
        apt: %w[jq], dnf: %w[jq], pacman: %w[jq], brew: %w[jq], port: %w[jq],
        plugins: %w[extro_osint]
      }
    }.freeze

    # Capability profiles — how you get the ergonomics of `pwn-full`
    # without shipping a second gem. `pwn setup --profile <name>`.
    PROFILES = {
      core: {
        desc: '~/.pwn bootstrap + vault + REPL (always runs on bare `pwn setup --deps`)',
        gems: %w[ffi nokogiri curses eventmachine],
        bins: %w[]
      },
      ai: {
        desc: 'verify at least one AI engine key/oauth in ~/.pwn/pwn.yaml',
        gems: %w[],
        bins: %w[jq]
      },
      web: {
        desc: 'TransparentBrowser · BurpSuite · Zaproxy · extro_verify · extro_watch',
        gems: %w[nokogiri eventmachine],
        bins: %w[chromium geckodriver burpsuite zaproxy sqlmap tor]
      },
      net: {
        desc: 'NmapIt · Packet · extro_packet · extro_osint',
        gems: %w[pcaprub],
        bins: %w[nmap tshark tcpdump whois jq]
      },
      db: {
        desc: 'DAOPostgres · DAOSqlite3 · DAOMongo',
        gems: %w[pg sqlite3],
        bins: %w[]
      },
      sdr: {
        desc: 'PWN::SDR · GQRX · FFI DSP backends · extro_rf_tune',
        gems: %w[ruby-audio libusb ffi],
        bins: %w[gqrx rtl_sdr hackrf_info SoapySDRUtil multimon-ng sox]
      },
      vision: {
        desc: 'OCR · ScannableCodes · Reports · extro_vision',
        gems: %w[rmagick rtesseract oily_png gruff],
        bins: %w[tesseract zbarimg dot]
      },
      voice: {
        desc: 'PWN::Plugins::Voice · extro_voice',
        gems: %w[ruby-audio],
        bins: %w[espeak-ng sox]
      },
      exploit: {
        desc: 'Metasploit · sqlmap',
        gems: %w[],
        bins: %w[msfconsole sqlmap]
      },
      hardware: {
        desc: 'Serial · BusPirate · Android · BareSIP · extro_serial · extro_telecomm',
        gems: %w[libusb],
        bins: %w[adb baresip]
      },
      full: {
        desc: 'everything above',
        gems: NATIVE_GEMS.keys,
        bins: TOOLCHAIN.keys
      }
    }.freeze

    OK   = "\e[32mok\e[0m"
    MISS = "\e[31mMISSING\e[0m"

    # Supported Method Parameters::
    # PWN::Setup.pkg_manager

    public_class_method def self.pkg_manager
      return @pkg_manager if defined?(@pkg_manager) && @pkg_manager

      # Drop the `sudo` prefix when we are already root (Docker / CI
      # containers, `sudo -i`, root shells) or when `sudo` is not
      # installed — otherwise `pwn setup --profile x --yes` dies with
      # `sh: sudo: not found` on stock debian:* / fedora:* images.
      root = begin
        Process.uid.zero?
      rescue StandardError
        false
      end
      sudo = root || !bin?(name: 'sudo') ? '' : 'sudo '

      @pkg_manager =
        if bin?(name: 'apt-get')     then { key: :apt,    install: "#{sudo}apt-get install -y",    sudo: !sudo.empty? }
        elsif bin?(name: 'dnf')      then { key: :dnf,    install: "#{sudo}dnf install -y",        sudo: !sudo.empty? }
        elsif bin?(name: 'pacman')   then { key: :pacman, install: "#{sudo}pacman -S --noconfirm", sudo: !sudo.empty? }
        elsif bin?(name: 'brew')     then { key: :brew,   install: 'brew install',                 sudo: false        }
        elsif bin?(name: 'port')     then { key: :port,   install: "#{sudo}port -N install",       sudo: !sudo.empty? }
        else { key: :unknown, install: nil, sudo: false }
        end
    end

    # Supported Method Parameters::
    # PWN::Setup.check(
    #   io: 'optional - IO to write the report to (default $stdout)'
    # )

    public_class_method def self.check(opts = {})
      io = opts[:io] || $stdout
      pm = pkg_manager
      os = detect_os_attr(attr: :type, fallback: RbConfig::CONFIG['host_os'])
      arch = detect_os_attr(attr: :arch, fallback: RbConfig::CONFIG['host_cpu'])

      io.puts "PWN v#{PWN::VERSION} · ruby #{RUBY_VERSION} · #{os} #{arch} · pkg-manager: #{pm[:key]}"
      io.puts

      # ~/.pwn -----------------------------------------------------------
      pwn_root  = File.join(Dir.home, '.pwn')
      pwn_yaml  = File.join(pwn_root, 'pwn.yaml')
      pwn_dec   = File.join(pwn_root, 'pwn.yaml.decryptor')
      root_ok   = File.directory?(pwn_root)
      root_note = root_ok ? "(#{Dir.children(pwn_root).length} entries)" : '(will be created on first `pwn` launch)'
      io.puts "#{'~/.pwn/'.ljust(26)} #{root_ok ? OK : MISS}   #{root_note}"
      yaml_ok   = File.file?(pwn_yaml)
      dec_state = File.file?(pwn_dec) ? 'present' : 'MISSING'
      yaml_note = yaml_ok ? "(encrypted, decryptor #{dec_state})" : '(run `pwn` once, then `pwn-vault` to configure)'
      io.puts "#{'~/.pwn/pwn.yaml'.ljust(26)} #{yaml_ok ? OK : MISS}   #{yaml_note}"
      engine = ai_active_engine
      key_ok = ai_key_configured?(engine: engine)
      engine_note = if engine
                      "#{engine} #{key_ok ? '(key set)' : '(no key — set via `pwn-vault`)'}"
                    else
                      '(no ai.active in pwn.yaml)'
                    end
      io.puts "#{'AI engine'.ljust(26)} #{key_ok ? OK : MISS}   #{engine_note}"
      io.puts

      # Native gems ------------------------------------------------------
      io.puts 'Ruby extensions'
      gem_missing = []
      NATIVE_GEMS.each do |gem_name, meta|
        ok = gem_loadable?(name: gem_name)
        gem_missing << gem_name unless ok
        need = ok ? '' : "(needs: #{Array(meta[pm[:key]]).join(' ')})"
        io.puts "  #{gem_name.to_s.ljust(14)} #{ok ? OK : MISS}  #{need.ljust(42)} → #{Array(meta[:plugins]).join(', ')}"
      end
      io.puts

      # Toolchain --------------------------------------------------------
      io.puts "#{'External toolchain'.ljust(46)} used by"
      bin_missing = []
      TOOLCHAIN.each do |bin, meta|
        path = which(name: bin)
        bin_missing << bin if path.empty?
        shown_path = path.empty? ? '' : path[0, 24]
        io.puts "  #{bin.to_s.ljust(16)} #{path.empty? ? MISS : OK}   #{shown_path.ljust(24)} #{Array(meta[:plugins]).join(', ')}"
      end
      io.puts

      # ~/.pwn state ----------------------------------------------------
      migrate = nil
      if defined?(PWN::Migrate)
        migrate = PWN::Migrate.check(io: io)
        io.puts
      end

      total   = NATIVE_GEMS.size + TOOLCHAIN.size
      missing = gem_missing.size + bin_missing.size
      io.puts "#{total - missing} / #{total} capabilities usable · #{missing} degraded"
      io.puts
      unless missing.zero?
        io.puts 'Run `pwn setup --deps` to install missing OS headers/tools, or'
        io.puts '    `pwn setup --profile <name>` for a subset. See `pwn setup --list-profiles`.'
      end

      { ok: missing.zero? && Array(migrate && migrate[:incompatible]).empty?,
        native_gems_missing: gem_missing, toolchain_missing: bin_missing,
        state: migrate, pkg_manager: pm[:key], os: os, arch: arch }
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Setup.deps(
    #   profile: 'optional - one of PROFILES.keys (default :full)',
    #   yes:     'optional - non-interactive; assume yes to prompts (default false)',
    #   dry_run: 'optional - print commands only, do not execute (default false)',
    #   io:      'optional - IO to write to (default $stdout)'
    # )

    public_class_method def self.deps(opts = {})
      profile = (opts[:profile] || :full).to_sym
      yes     = opts[:yes] ? true : false
      dry_run = opts[:dry_run] ? true : false
      io      = opts[:io] || $stdout

      raise "Unknown profile '#{profile}'. Known: #{PROFILES.keys.join(', ')}" unless PROFILES.key?(profile)

      pm = pkg_manager
      raise 'No supported package manager found (apt / dnf / pacman / brew / port).' if pm[:key] == :unknown

      prof     = PROFILES[profile]
      gems     = Array(prof[:gems])
      # Drop setup-managed gems whose upstream required_ruby_version excludes
      # THIS ruby (e.g. meshtastic >= 4.0 on a distro ruby 3.3) — otherwise
      # `gem install` in the loop below fails and takes the whole profile with it.
      gems = gems.reject do |g|
        floor = NATIVE_GEMS.dig(g, :min_ruby)
        skip  = floor && Gem::Version.new(RUBY_VERSION) < Gem::Version.new(floor)
        io.puts "  \e[33mskip\e[0m #{g} — requires ruby >= #{floor} (running #{RUBY_VERSION})" if skip
        skip
      end
      bins     = Array(prof[:bins])
      os_pkgs  = []
      gems.each { |g| os_pkgs.concat(Array(NATIVE_GEMS.dig(g, pm[:key]))) }
      bins.each { |b| os_pkgs.concat(Array(TOOLCHAIN.dig(b, pm[:key]))) }
      os_pkgs = os_pkgs.reject(&:empty?).uniq

      io.puts "Profile   : #{profile} — #{prof[:desc]}"
      io.puts "Pkg mgr   : #{pm[:key]}"
      io.puts "OS pkgs   : #{os_pkgs.empty? ? '(none)' : os_pkgs.join(' ')}"
      io.puts "Ruby exts : #{gems.empty? ? '(none)' : gems.join(' ')}"
      io.puts

      cmds = []
      cmds << "#{pm[:install]} #{os_pkgs.map { |p| Shellwords.escape(p) }.join(' ')}" unless os_pkgs.empty?
      unless gems.empty?
        broken = gems.reject { |g| gem_loadable?(name: g) }
        cmds << "gem pristine #{broken.map { |g| Shellwords.escape(g) }.join(' ')}" unless broken.empty?
        cmds << "gem install #{broken.map { |g| Shellwords.escape(g) }.join(' ')}"  unless broken.empty?
      end

      if cmds.empty?
        io.puts "Nothing to do — profile '#{profile}' is already satisfied."
        return { profile: profile, ran: [], skipped: true }
      end

      io.puts 'Will run:'
      cmds.each { |c| io.puts "  $ #{c}" }
      io.puts

      unless yes || dry_run
        io.print 'Proceed? [y/N] '
        ans = $stdin.gets.to_s.strip.downcase
        return { profile: profile, ran: [], aborted: true } unless %w[y yes].include?(ans)
      end

      ran = []
      cmds.each do |c|
        io.puts "→ #{c}"
        if dry_run
          ran << { cmd: c, exit: 0, dry_run: true }
        else
          ok = system(c)
          ran << { cmd: c, exit: $CHILD_STATUS && $CHILD_STATUS.exitstatus, ok: ok }
          io.puts "  (exit #{ran.last[:exit]})" unless ok
        end
      end

      io.puts
      io.puts 'Re-checking…'
      io.puts
      result = check(io: io)
      { profile: profile, ran: ran, check: result }
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Setup.list_profiles(
    #   io: 'optional - IO to write to (default $stdout)'
    # )

    public_class_method def self.list_profiles(opts = {})
      io = opts[:io] || $stdout
      io.puts 'Available capability profiles (`pwn setup --profile <name>`):'
      io.puts
      PROFILES.each do |name, meta|
        io.puts "  #{name.to_s.ljust(10)} #{meta[:desc]}"
        io.puts "  #{''.ljust(10)}   gems: #{meta[:gems].join(' ')}" unless meta[:gems].empty?
        io.puts "  #{''.ljust(10)}   bins: #{meta[:bins].join(' ')}" unless meta[:bins].empty?
        io.puts
      end
      PROFILES.keys
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Setup.migrate(
    #   fix:     'optional - also autofix incompatible ~/.pwn files (default false)',
    #   dry_run: 'optional - print what WOULD happen (default false)',
    #   yes:     'optional - alias for fix:true (CI-friendly)',
    #   io:      'optional - IO to write to (default $stdout)'
    # )
    #
    # Delegate to PWN::Migrate.run — verify every ~/.pwn state file is
    # compatible with THIS pwn release and (optionally) autofix it.  A
    # timestamped backup of ~/.pwn is taken first.  See `PWN::Migrate.help`.

    public_class_method def self.migrate(opts = {})
      PWN::Migrate.run(
        fix: opts[:fix] || opts[:yes],
        dry_run: opts[:dry_run],
        io: opts[:io] || $stdout
      )
    rescue StandardError => e
      raise e
    end

    # ------------------------------------------------------------------

    private_class_method def self.detect_os_attr(opts = {})
      PWN::Plugins::DetectOS.public_send(opts[:attr])
    rescue StandardError
      opts[:fallback]
    end

    private_class_method def self.ai_active_engine
      PWN::Env.dig(:ai, :active)
    rescue StandardError
      nil
    end

    private_class_method def self.ai_key_configured?(opts = {})
      engine = opts[:engine]
      return false unless engine

      PWN::Env.dig(:ai, engine.to_sym, :key).to_s !~ /\A(required|optional|)\z/i
    rescue StandardError
      false
    end

    private_class_method def self.bin?(opts = {})
      !which(name: opts[:name]).empty?
    end

    private_class_method def self.which(opts = {})
      name = opts[:name].to_s
      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
        path = File.join(dir, name)
        return path if File.executable?(path) && !File.directory?(path)
      end
      ''
    end

    private_class_method def self.gem_loadable?(opts = {})
      name = opts[:name].to_s
      Gem::Specification.find_by_name(name)
      true
    rescue StandardError
      # Fall back to require in case the ext is present but spec lookup lies
      begin
        require name.tr('-', '/')
        true
      rescue StandardError
        false
      end
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
        # Read-only doctor — which PWN capabilities are usable on this host?
        #{self}.check

        # Install OS headers + rebuild native gems for a capability profile.
        # profile ∈ #{PROFILES.keys.inspect}
        #{self}.deps(
          profile: 'optional - capability profile (default :full)',
          yes:     'optional - assume yes (non-interactive)',
          dry_run: 'optional - print commands only'
        )

        # List capability profiles.
        #{self}.list_profiles

        # Detected package manager (:apt / :dnf / :pacman / :brew / :port).
        #{self}.pkg_manager

        # Data tables — versioned with the gem:
        #{self}::NATIVE_GEMS   # native ext → OS headers → PWN:: constants
        #{self}::TOOLCHAIN     # external bin → OS package → PWN:: constants
        #{self}::PROFILES      # capability profile → gems + bins

        # From the shell:
        pwn setup                       # == check
        pwn setup --check
        pwn setup --deps                # profile :full
        pwn setup --profile web
        pwn setup --profile sdr --yes
        pwn setup --list-profiles
        pwn setup --dry-run --profile net
        pwn setup --migrate                  # verify + upgrade ~/.pwn schema
        pwn setup --migrate --fix            # also autofix incompatible files

        #{self}.authors
      "
    end
  end
end
