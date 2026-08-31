# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # Frida attach/spawn + script injection.
    module Frida
      SSL_PINNING = <<~JS
        Java.perform(function () {
          try {
            var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManagers = [Java.registerClass({
              name: 'pwn.TrustAll',
              implements: [TrustManager],
              methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
              }
            }).$new()];
            var ctx = SSLContext.getInstance('TLS');
            ctx.init(null, TrustManagers, null);
            SSLContext.getDefault.implementation = function () { return ctx; };
          } catch (e) {}
        });
      JS

      public_class_method def self.required_bins
        %w[frida]
      end

      public_class_method def self.ps(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'frida')
        stdout, stderr, status = Open3.capture3('frida-ps', *Array(opts[:extra]))
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.attach(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'frida')
        target = opts[:target] || opts[:name]
        script = opts[:script].to_s
        raise 'ERROR: target is required' if target.to_s.empty?

        cmd = ['frida', '-n', target.to_s]
        cmd += ['-l', opts[:script_path].to_s] if opts[:script_path]
        cmd += ['-e', script] unless script.empty?
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.spawn(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'frida')
        path = (opts[:path] || opts[:file]).to_s
        raise 'ERROR: path is required' if path.empty?

        cmd = ['frida', '-f', path]
        cmd += ['-l', opts[:script_path].to_s] if opts[:script_path]
        cmd += ['-e', opts[:script].to_s] unless opts[:script].to_s.empty?
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.ssl_pinning_script(opts = {})
        opts[:android]
        SSL_PINNING
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # List processes via frida-ps.
          #{self}.ps(
            extra: 'optional - extra frida-ps argv'
          )

          # Attach to a running process and optionally inject a script.
          #{self}.attach(
            target: 'required - process name (defaults to opts[:name])',
            name: 'optional - alias for target',
            script: 'optional - JavaScript source to pass with -e',
            script_path: 'optional - path to a .js file for -l'
          )

          # Spawn a binary under Frida and inject a script.
          #{self}.spawn(
            path: 'required - filesystem path to the binary',
            file: 'optional - alias for path',
            script: 'optional - JavaScript source to pass with -e',
            script_path: 'optional - path to a .js file for -l'
          )

          # Return an SSL-pinning bypass JavaScript template.
          #{self}.ssl_pinning_script(
            android: 'optional - currently always returns the Java TrustManager template'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
