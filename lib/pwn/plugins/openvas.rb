# frozen_string_literal: true

require 'nokogiri'
require 'time'
require 'base64'

module PWN
  module Plugins
    # This plugin is used for interacting w/ OpenVAS using OMP (OpenVAS Management Protocol).
    module OpenVAS
      # Supported Method Parameters::
      # task_xml_resp = PWN::Plugins::OpenVAS.get_task_id(
      #   task_name: 'required task name to start',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.get_task_id(opts = {})
        task_name = opts[:task_name].to_s.scrub
        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        get_tasks_xml_resp = Nokogiri::XML(
          `sudo runuser -u _gvm -- /usr/bin/gvm-cli \
            --gmp-username '#{username}' \
            --gmp-password '#{password}' \
            socket \
            --xml="<get_tasks/>"
          `
        )

        get_tasks_xml_resp.xpath(
          "/get_tasks_response/task[name/text()='#{task_name}']"
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # start_task_xml_resp = PWN::Plugins::OpenVAS.start_task(
      #   task_name: 'required task name to start',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.start_task(opts = {})
        task_name = opts[:task_name].to_s.scrub
        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        task_id = get_task_id(
          task_name: task_name,
          username: username,
          password: password
        ).xpath('@id').text

        Nokogiri::XML(
          `sudo runuser -u _gvm -- /usr/bin/gvm-cli \
            --gmp-username '#{username}' \
            --gmp-password '#{password}' \
            socket \
            --xml="<start_task task_id='#{task_id}'/>"
          `
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # task_status = PWN::Plugins::OpenVAS.get_task_status(
      #   task_name: 'required task name to start',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.get_task_status(opts = {})
        task_name = opts[:task_name].to_s.scrub
        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        get_task_id(
          task_name: task_name,
          username: username,
          password: password
        ).xpath('status').text
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # last_report_id = PWN::Plugins::OpenVAS.last_report_id(
      #   task_name: 'required task name to start',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.last_report_id(opts = {})
        task_name = opts[:task_name].to_s.scrub
        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        task_id = get_task_id(
          task_name: task_name,
          username: username,
          password: password
        ).xpath('@id').text

        report_xml_resp = Nokogiri::XML(
          `sudo runuser -u _gvm -- /usr/bin/gvm-cli \
            --gmp-username '#{username}' \
            --gmp-password '#{password}' \
            socket \
            --xml="<get_reports/>"
          `
        )

        report_xml_resp.xpath(
          "/get_reports_response/report/task[@id='#{task_id}']"
        ).last.parent.xpath(
          '@id'
        ).text
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::OpenVAS.save_report(
      #   report_type: 'required report type (csv|itg|pdf|txt|xml)',
      #   report_id: 'required report id to save',
      #   report_filter: 'optional - results filter (Default: "")
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.save_report(opts = {})
        report_type = opts[:report_type].to_s.scrub
        report_id = opts[:report_id].to_s.scrub
        report_dir = opts[:report_dir].to_s.scrub
        raise "#{report_dir} Does Not Exist." unless Dir.exist?(
          report_dir
        )

        report_filter = opts[:report_filter]
        report_filter ||= 'apply_overrides=0 levels=hml rows=1000 min_qod=70 first=1 sort-reverse=severity'

        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        case report_type.to_sym
        when :csv
          report_type_name = 'CSV Results'
        when :itg
          report_type_name = 'ITG'
        when :pdf
          report_type_name = 'PDF'
        when :txt
          report_type_name = 'TXT'
        when :xml
          report_type_name = 'XML'
        else
          raise "Report Type: \"#{report_type}\" not supported."
        end

        report_formats_xml_resp = Nokogiri::XML(
          `sudo runuser -u _gvm -- /usr/bin/gvm-cli \
            --gmp-username '#{username}' \
            --gmp-password '#{password}' \
            socket \
            --xml="<get_report_formats/>"
          `
        )

        rpt_fmt_xml_resp_by_name = report_formats_xml_resp.xpath(
          "/get_report_formats_response/report_format[name/text()='#{report_type_name}']"
        )

        format_id = rpt_fmt_xml_resp_by_name.xpath('@id').text

        # Generate Report
        report_xml_resp = Nokogiri::XML(
          `sudo runuser -u _gvm -- /usr/bin/gvm-cli \
            --gmp-username '#{username}' \
            --gmp-password '#{password}' \
            socket \
            --xml="<get_reports report_id='#{report_id}' format_id='#{format_id}' filter='#{report_filter}' details='1' />"
          `
        )

        # timestamp = Time.parse(
        #   report_xml_resp.xpath('//modification_time')
        # ).localtime.strftime(
        #   '%Y-%m-%d-%H-%M-%S%z'
        # )

        base64_report = report_xml_resp.xpath(
          '//report/text()'
        ).text

        # File.open("#{report_dir}/openvas_results-#{timestamp}.#{report_type}", 'w') do |f|
        File.open("#{report_dir}/openvas_results.#{report_type}", 'w') do |f|
          f.puts Base64.strict_decode64(base64_report)
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # report_types = PWN::Plugins::OpenVAS.get_report_types(
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.get_report_types(opts = {})
        username = opts[:username].to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        report_types = %i[
          csv
          itg
          pdf
          txt
          xml
        ]
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          task_xml_resp = #{self}.get_task_id(
            task_name: 'required task name to start',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          start_task_xml_resp = #{self}.start_task(
            task_name: 'required task name to start',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          task_status = #{self}.get_task_status(
            task_name: 'required task name to start',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          last_report_id = #{self}.last_report_id(
            task_name: 'required task name to start',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          #{self}.save_report(
            report_type: 'required report type (csv|itg|pdf|txt|xml)',
            report_id: 'required report id to save',
            report_dir: 'required directory to save report',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          report_types = #{self}.get_report_types(
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          #{self}.authors
        "
      end
    end
  end
end
