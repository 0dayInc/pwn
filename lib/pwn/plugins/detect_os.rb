# frozen_string_literal: true

require 'os'

module PWN
  module Plugins
    # Detect host OS family, distro flavor, and version string.
    module DetectOS
      ID_ALIASES = {
        'chromiumos' => :chromeos,
        'chromeos' => :chromeos,
        'pop_os' => :pop,
        'pop' => :pop,
        'ol' => :oracle,
        'opensuse-leap' => :opensuse,
        'opensuse-tumbleweed' => :opensuse,
        'sles' => :suse,
        'darwin' => :macos,
        'osx' => :macos,
        'macos' => :macos,
        'iphoneos' => :ios,
        'ipados' => :ios,
        'ios' => :ios,
        'win32' => :windows,
        'mingw32' => :windows,
        'mingw' => :windows,
        'mswin' => :windows
      }.freeze

      public_class_method def self.type
        os = :cygwin if OS.cygwin?
        os = :freebsd if OS.freebsd?
        os = :linux if OS.linux?
        os = :netbsd if OS.host_os.to_s.include?('netbsd')
        os = :openbsd if OS.host_os.to_s.include?('openbsd')
        os = :osx if OS.osx?
        os = :windows if OS.windows?
        if os.nil?
          uname = `uname -s 2>/dev/null`.to_s.downcase
          os = :openbsd if uname.include?('openbsd')
          os = :freebsd if uname.include?('freebsd')
          os = :netbsd if uname.include?('netbsd')
          os = :linux if uname.include?('linux')
        end

        os
      rescue StandardError => e
        raise e
      end

      public_class_method def self.arch
        OS.host_cpu
      rescue StandardError => e
        raise e
      end

      public_class_method def self.endian
        if [1].pack('I') == [1].pack('N')
          :big
        else
          :little
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.distro(
      #   os_release: 'optional - /etc/os-release body (defaults to reading the file)',
      #   lsb_release: 'optional - /etc/lsb-release body',
      #   build_prop: 'optional - Android /system/build.prop body',
      #   type: 'optional - OS family from #type (e.g. :linux :osx :windows :freebsd)',
      #   platform: 'optional - RUBY_PLATFORM override',
      #   uname: 'optional - uname -s string',
      #   sw_vers: 'optional - macOS/iOS product version string',
      #   win_ver: 'optional - Windows ver command output'
      # )

      public_class_method def self.distro(opts = {})
        return normalize_id(id: opts[:distro]) if opts[:distro]

        platform = (opts[:platform] || RUBY_PLATFORM).to_s.downcase
        uname = (opts[:uname] || live_uname_s).to_s.downcase
        os_type = opts[:type] || type
        osr = parse_kv(content: opts[:os_release] || read_if_present(path: '/etc/os-release') || read_if_present(path: '/usr/lib/os-release'))
        lsb = parse_kv(content: opts[:lsb_release] || read_if_present(path: '/etc/lsb-release'))
        prop = parse_kv(content: opts[:build_prop] || read_if_present(path: '/system/build.prop'))

        return :ios if ios_host?(platform: platform, uname: uname)
        return :android if android_host?(osr: osr, prop: prop, uname: uname)
        return :chromeos if chromeos_host?(osr: osr, lsb: lsb)
        return :macos if os_type == :osx || platform.include?('darwin')
        return :windows if os_type == :windows || platform.match?(/mswin|mingw|cygwin/)
        return :freebsd if os_type == :freebsd || uname.include?('freebsd')
        return :openbsd if os_type == :openbsd || uname.include?('openbsd')
        return :netbsd if os_type == :netbsd || uname.include?('netbsd')
        return :dragonfly if uname.include?('dragonfly')
        return :cygwin if os_type == :cygwin

        id = osr['ID'].to_s
        return normalize_id(id: id) unless id.empty?

        like = osr['ID_LIKE'].to_s.downcase
        return :debian if like.include?('debian')
        return :fedora if like.include?('fedora') || like.include?('rhel')
        return :arch if like.include?('arch')
        return :suse if like.include?('suse')

        os_type || :unknown
      end

      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.version(
      #   os_release: 'optional - /etc/os-release body',
      #   lsb_release: 'optional - /etc/lsb-release body',
      #   build_prop: 'optional - Android build.prop body',
      #   sw_vers: 'optional - macOS/iOS product version',
      #   win_ver: 'optional - Windows ver output',
      #   uname_r: 'optional - uname -r string',
      #   type: 'optional - OS family from #type'
      # )

      public_class_method def self.version(opts = {})
        return opts[:version].to_s if opts[:version]

        injected = %i[os_release lsb_release build_prop sw_vers win_ver uname_r].any? { |k| opts.key?(k) }
        os_type = opts[:type] || type
        osr = parse_kv(content: opts[:os_release] || (injected ? nil : read_if_present(path: '/etc/os-release') || read_if_present(path: '/usr/lib/os-release')))
        lsb = parse_kv(content: opts[:lsb_release] || (injected ? nil : read_if_present(path: '/etc/lsb-release')))
        prop = parse_kv(content: opts[:build_prop] || (injected ? nil : read_if_present(path: '/system/build.prop')))

        from_osr = osr['VERSION_ID'].to_s
        return from_osr unless from_osr.empty?

        chrome = lsb['CHROMEOS_RELEASE_VERSION'].to_s
        return chrome unless chrome.empty?

        android = prop['ro.build.version.release'].to_s
        return android unless android.empty?

        if os_type == :osx || opts[:sw_vers]
          mac = (opts[:sw_vers] || live_sw_vers).to_s.strip
          return mac unless mac.empty?
        end

        if os_type == :windows || opts[:win_ver]
          win = (opts[:win_ver] || live_win_ver).to_s
          m = win.match(/\[Version\s+([^\]]+)\]/i) || win.match(/(\d+\.\d+(?:\.\d+)*)/)
          return m[1] if m
        end

        rel = (opts[:uname_r] || live_uname_r).to_s.strip
        return rel if %i[freebsd openbsd netbsd].include?(os_type) && !rel.empty?

        debian = read_if_present(path: '/etc/debian_version').to_s.strip
        return debian unless debian.empty?

        osr['VERSION'].to_s
      end

      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.living_off_the_land(
      #   os_release: 'optional - /etc/os-release body (defaults to reading the file)',
      #   which: 'optional - Hash of binary name => present Boolean (skips live PATH)',
      #   bins: 'optional - extra host binary names to include when present',
      #   pwn_bins: 'optional - Array of names pwn setup already installs (skipped)'
      # )

      public_class_method def self.living_off_the_land(opts = {})
        os_type = opts[:type] || type
        flavor = distro(opts)
        ver = version(opts)
        cpu = opts[:arch] || arch
        endn = opts[:endian] || endian
        found = host_path_names(opts)
        extra = Array(opts[:bins]).map(&:to_s).reject(&:empty?)
        extra.each do |name|
          ok = if opts[:which].is_a?(Hash)
                 opts[:which][name] || opts[:which][name.to_sym]
               else
                 bin_present?(name: name)
               end
          found << name if ok
        end
        native = found.map(&:to_s).reject(&:empty?).uniq.sort
        cap = if opts.key?(:cap_net_raw)
                opts[:cap_net_raw]
              else
                cap_net_raw_live
              end
        docker = if opts.key?(:docker)
                   opts[:docker]
                 else
                   docker_live
                 end
        summary = "#{flavor} #{ver} #{cpu}"
        {
          type: os_type,
          distro: flavor,
          version: ver,
          arch: cpu.to_s,
          endian: endn,
          native: native,
          cap_net_raw: cap,
          docker: docker,
          summary: summary
        }
      end

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      public_class_method def self.help
        puts "USAGE:
          # Return the OS family as a symbol (:linux :osx :windows :freebsd :openbsd :netbsd :cygwin).
          #{self}.type

          # Return the CPU architecture string from the host (e.g. x86_64, arm64).
          #{self}.arch

          # Return CPU endianness as :little or :big.
          #{self}.endian

          # Return the distro flavor as a lowercase symbol (:kali :ubuntu :macos :windows :freebsd …).
          #{self}.distro(
            os_release: 'optional - /etc/os-release body (defaults to reading the file)',
            lsb_release: 'optional - /etc/lsb-release body',
            build_prop: 'optional - Android /system/build.prop body',
            type: 'optional - OS family from #type (e.g. :linux :osx :windows :freebsd)',
            platform: 'optional - RUBY_PLATFORM override (detect iOS/Android/Windows)',
            uname: 'optional - uname -s string',
            sw_vers: 'optional - macOS/iOS product version string',
            win_ver: 'optional - Windows ver command output',
            distro: 'optional - force a distro id instead of detecting'
          )

          # Return the distro version as a string (e.g. 2026.3, 24.04, 15.1, 14.1-RELEASE).
          #{self}.version(
            os_release: 'optional - /etc/os-release body',
            lsb_release: 'optional - /etc/lsb-release body',
            build_prop: 'optional - Android build.prop body',
            sw_vers: 'optional - macOS/iOS product version',
            win_ver: 'optional - Windows ver output',
            uname_r: 'optional - uname -r string',
            type: 'optional - OS family from #type',
            version: 'optional - force a version string instead of detecting'
          )

          # Inventory extra PATH binaries on this host that pwn plugins do not already wrap.
          #{self}.living_off_the_land(
            os_release: 'optional - /etc/os-release body (defaults to reading the file)',
            lsb_release: 'optional - /etc/lsb-release body',
            build_prop: 'optional - Android /system/build.prop body',
            type: 'optional - OS family from #type',
            which: 'optional - Hash of binary name => true/false (skips live PATH when set)',
            bins: 'optional - extra host binary names to include when present on PATH',
            pwn_bins: 'optional - extra names to treat as already wrapped (skipped from native)',
            arch: 'optional - CPU arch override',
            endian: 'optional - :little or :big override',
            cap_net_raw: 'optional - Boolean CAP_NET_RAW override',
            docker: 'optional - Boolean docker.sock override'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.host_path_names(opts = {})
        return Array(opts[:path_names]).map(&:to_s) if opts.key?(:path_names)

        if opts.key?(:which)
          which = opts[:which]
          return [] unless which.is_a?(Hash)

          return which.select { |_n, ok| ok }.keys.map(&:to_s)
        end

        scan_path_executables
      end

      private_class_method def self.scan_path_executables(opts = {})
        return [] if opts[:skip]

        names = []
        ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
          next unless File.directory?(dir)

          Dir.children(dir).each do |base|
            path = File.join(dir, base)
            next unless File.file?(path) && File.executable?(path)

            names << base.sub(/\.(exe|bat|cmd|com)\z/i, '')
          end
        rescue StandardError
          next
        end
        names.uniq
      end

      private_class_method def self.pwn_installed_bins(opts = {})
        extra = Array(opts[:pwn_bins]).map(&:to_s)
        deps = if defined?(PWN::Plugins::PreflightChecker::PLUGIN_DEPS)
                 PWN::Plugins::PreflightChecker::PLUGIN_DEPS.values.flat_map { |row| Array(row[:bins]).map(&:to_s) }
               else
                 []
               end
        (extra + deps).reject(&:empty?).uniq
      end

      private_class_method def self.bin_present?(opts = {})
        name = opts[:name].to_s
        return false if name.empty?
        return PWN::Plugins::PreflightChecker.bin?(name: name) if defined?(PWN::Plugins::PreflightChecker)

        ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, name)) }
      rescue StandardError
        false
      end

      private_class_method def self.cap_net_raw_live
        return unless defined?(PWN::Plugins::PreflightChecker)

        PWN::Plugins::PreflightChecker.cap_net_raw?
      rescue StandardError
        nil
      end

      private_class_method def self.docker_live
        return unless defined?(PWN::Plugins::PreflightChecker)

        PWN::Plugins::PreflightChecker.service?(name: 'docker', path: '/var/run/docker.sock')
      rescue StandardError
        nil
      end

      private_class_method def self.normalize_id(opts = {})
        raw = opts[:id].to_s.downcase.strip.gsub(/["']/, '')
        return :unknown if raw.empty?

        ID_ALIASES[raw] || raw.tr('-', '_').to_sym
      end

      private_class_method def self.parse_kv(opts = {})
        content = opts[:content].to_s
        return {} if content.empty?

        content.each_line.with_object({}) do |line, acc|
          next if line.strip.empty? || line.strip.start_with?('#')

          key, val = line.split('=', 2)
          next unless val

          acc[key.strip] = val.strip.gsub(/\A["']|["']\z/, '')
        end
      end

      private_class_method def self.read_if_present(opts = {})
        path = opts[:path].to_s
        return unless File.readable?(path)

        File.read(path)
      rescue StandardError
        nil
      end

      private_class_method def self.ios_host?(opts = {})
        blob = "#{opts[:platform]} #{opts[:uname]}"
        blob.match?(/iphone|ipad|ios/)
      end

      private_class_method def self.android_host?(opts = {})
        osr = opts[:osr] || {}
        prop = opts[:prop] || {}
        uname = opts[:uname].to_s
        osr['ID'].to_s.downcase == 'android' ||
          !prop['ro.build.version.release'].to_s.empty? ||
          uname.include?('android') ||
          File.exist?('/system/build.prop')
      end

      private_class_method def self.chromeos_host?(opts = {})
        osr = opts[:osr] || {}
        lsb = opts[:lsb] || {}
        id = osr['ID'].to_s.downcase
        id == 'chromeos' || id == 'chromiumos' ||
          !lsb['CHROMEOS_RELEASE_NAME'].to_s.empty? ||
          !lsb['CHROMEOS_RELEASE_VERSION'].to_s.empty?
      end

      private_class_method def self.live_uname_s(opts = {})
        opts[:skip]
        `uname -s 2>/dev/null`.to_s
      rescue StandardError
        ''
      end

      private_class_method def self.live_uname_r(opts = {})
        opts[:skip]
        `uname -r 2>/dev/null`.to_s
      rescue StandardError
        ''
      end

      private_class_method def self.live_sw_vers(opts = {})
        opts[:skip]
        `sw_vers -productVersion 2>/dev/null`.to_s
      rescue StandardError
        ''
      end

      private_class_method def self.live_win_ver(opts = {})
        opts[:skip]
        `ver 2>NUL`.to_s
      rescue StandardError
        ''
      end
    end
  end
end
