# frozen_string_literal: true

require 'mail'
require 'base64'
require 'socket'

module PWN
  module Plugins
    # This is a fork of the no-longer maintained 'pony' gem.
    # This module's purpose is to exist until the necessary
    # functionality can be integrated into PWN::Plugins::MailAgent
    module Pony
      @@logger = PWN::Plugins::PWNLogger.create
      @@options = {}
      @@override_options = {}
      @@subject_prefix = false
      @@append_inputs = false

      # Default options can be set so that they don't have to be repeated.
      #
      #   Pony.options = { :from => 'noreply@example.com', :via => :smtp, :via_options => { :host => 'smtp.yourserver.com' } }
      #   Pony.mail(:to => 'foo@bar') # Sends mail to foo@bar from noreply@example.com using smtp
      #   Pony.mail(:from => 'pony@example.com', :to => 'foo@bar') # Sends mail to foo@bar from pony@example.com using smtp
      public_class_method def self.options=(value)
        @@options = value
      end

      # Method usage N/A

      public_class_method def self.options
        @@options
      end

      # Method usage N/A

      public_class_method def self.override_options=(value)
        @@override_options = value
      end

      # Method usage N/A

      public_class_method def self.override_options
        @@override_options
      end

      # Method usage N/A

      public_class_method def self.subject_prefix(value)
        @@subject_prefix = value
      end

      # Method usage N/A

      public_class_method def self.append_inputs
        @@append_inputs = true
      end

      # Send an email
      #   Pony.mail(:to => 'you@example.com', :from => 'me@example.com', :subject => 'hi', :body => 'Hello there.')
      #   Pony.mail(:to => 'you@example.com', :html_body => '<h1>Hello there!</h1>', :body => "In case you can't read html, Hello there.")
      #   Pony.mail(:to => 'you@example.com', :cc => 'him@example.com', :from => 'me@example.com', :subject => 'hi', :body => 'Howsit!')
      public_class_method def self.mail(options)
        options[:body] = "#{options[:body]}/n #{options}" if @@append_inputs

        options = @@options.merge options
        options = options.merge @@override_options

        options[:subject] = "#{@@subject_prefix}#{options[:subject]}" if @@subject_prefix

        raise ArgumentError, ':to is required' unless options[:to]

        options[:via] = default_delivery_method unless options.key?(:via)

        if options.key?(:via) && options[:via] == :sendmail
          options[:via_options] ||= {}
          options[:via_options][:location] ||= sendmail_binary
        end

        deliver build_mail(options)
      end

      # Method usage N/A

      public_class_method def self.permissable_options
        standard_options + non_standard_options
      end

      # Method usage N/A

      private_class_method def self.deliver(mail)
        mail.deliver!
      end

      # Method usage N/A

      public_class_method def self.default_delivery_method
        File.executable?(sendmail_binary) ? :sendmail : :smtp
      end

      # Method usage N/A

      public_class_method def self.standard_options
        %i[
          to
          cc
          bcc
          from
          subject
          content_type
          message_id
          sender
          reply_to
          smtp_envelope_to
        ]
      end

      # Method usage N/A

      public_class_method def self.non_standard_options
        %i[
          attachments
          body
          charset
          enable_starttls_auto
          headers
          html_body
          text_part_charset
          via
          via_options
          body_part_header
          html_body_part_header
        ]
      end

      # Method usage N/A

      public_class_method def self.build_mail(options)
        mail = Mail.new do |m|
          options[:date] ||= Time.now
          options[:from] ||= 'pony@unknown'
          options[:via_options] ||= {}

          options.each do |k, v|
            next if non_standard_options.include?(k)

            m.send(k, v)
          end

          # Automatic handling of multipart messages in the underlying
          # mail library works pretty well for the most part, but in
          # the case where we have attachments AND text AND html bodies
          # we need to explicitly define a second multipart/alternative
          # boundary to encapsulate the body-parts within the
          # multipart/mixed boundary that will be created automatically.
          if options[:attachments] && options[:html_body] && options[:body]
            part(content_type: 'multipart/alternative') do |p|
              p.html_part = build_html_part(options)
              p.text_part = build_text_part(options)
            end

          # Otherwise if there is more than one part we still need to
          # ensure that they are all declared to be separate.
          elsif options[:html_body] || options[:attachments]
            m.html_part = build_html_part(options) if options[:html_body]

            m.text_part = build_text_part(options) if options[:body]

          elsif options[:body]
            # If all we have is a text body, we don't need to worry about parts.
            body options[:body]
          end

          m.delivery_method options[:via], options[:via_options]
        end

        (options[:headers] ||= {}).each do |key, value|
          mail[key] = value
        end

        add_attachments(mail, options[:attachments]) if options[:attachments]

        mail.charset = options[:charset] if options[:charset] # charset must be set after setting content_type

        mail.text_part.charset = options[:text_part_charset] if mail.multipart? && options[:text_part_charset]
        set_content_type(mail, options[:content_type])
        mail
      end

      # Method usage N/A

      public_class_method def self.build_html_part(options)
        Mail::Part.new(content_type: 'text/html;charset=UTF-8') do
          content_transfer_encoding 'quoted-printable'
          body Mail::Encodings::QuotedPrintable.encode(options[:html_body])
          if options[:html_body_part_header] && options[:html_body_part_header].is_a?(Hash)
            options[:html_body_part_header].each do |k, v|
              header[k] = v
            end
          end
        end
      end

      # Method usage N/A

      public_class_method def self.build_text_part(options)
        Mail::Part.new(content_type: 'text/plain') do
          content_type options[:charset] if options[:charset]
          body options[:body]
          if options[:body_part_header] && options[:body_part_header].is_a?(Hash)
            options[:body_part_header].each do |k, v|
              header[k] = v
            end
          end
        end
      end

      # Method usage N/A

      public_class_method def self.set_content_type(mail, user_content_type)
        params = mail.content_type_parameters || {}
        case params
        when user_content_type
          content_type = user_content_type
        when mail.has_attachments?
          if mail.attachments.detect(&:inline?)
            content_type = ['multipart', 'related', params]
          else
            content_type = ['multipart', 'mixed', params]
          end
        when mail.multipart?
          content_type = ['multipart', 'alternative', params]
        else
          content_type = false
        end
        mail.content_type = content_type if content_type
      end

      # Method usage N/A

      public_class_method def self.add_attachments(mail, attachments)
        attachments.each do |name, body|
          name = name.gsub(/\s+/, ' ')

          # mime-types wants to send these as "quoted-printable"
          if name.match?('.xlsx')
            mail.attachments[name] = {
              content: Base64.strict_encode64(body),
              transfer_encoding: :base64
            }
          else
            mail.attachments[name] = body
          end
          mail.attachments[name].add_content_id("<#{name}@#{Socket.gethostname}>")
        end
      end

      # Method usage N/A

      public_class_method def self.sendmail_binary
        sendmail = `which sendmail`.chomp
        sendmail.empty? ? '/usr/sbin/sendmail' : sendmail
      end

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          This module is deprecated.  Please Use PWN::Plugins::MailAgent instead.
          #{self}.authors
        "
      end
    end
  end
end
