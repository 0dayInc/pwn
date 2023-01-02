# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP plugins
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Plugins
    autoload :Android, 'pwn/plugins/android'
    autoload :AnsibleVault, 'pwn/plugins/ansible_vault'
    autoload :AuthenticationHelper, 'pwn/plugins/authentication_helper'
    autoload :BareSIP, 'pwn/plugins/baresip'
    autoload :BasicAuth, 'pwn/plugins/basic_auth'
    autoload :BeEF, 'pwn/plugins/beef'
    autoload :BurpSuite, 'pwn/plugins/burp_suite'
    autoload :BusPirate, 'pwn/plugins/bus_pirate'
    autoload :Char, 'pwn/plugins/char'
    autoload :ChatSonic, 'pwn/plugins/chat_sonic'
    autoload :CreditCard, 'pwn/plugins/credit_card'
    autoload :PWNLogger, 'pwn/plugins/pwn_logger'
    autoload :DAOLDAP, 'pwn/plugins/dao_ldap'
    autoload :DAOMongo, 'pwn/plugins/dao_mongo'
    autoload :DAOPostgres, 'pwn/plugins/dao_postgres'
    autoload :DAOSQLite3, 'pwn/plugins/dao_sqlite3'
    autoload :DefectDojo, 'pwn/plugins/defect_dojo'
    autoload :DetectOS, 'pwn/plugins/detect_os'
    autoload :EIN, 'pwn/plugins/ein'
    autoload :FileFu, 'pwn/plugins/file_fu'
    autoload :Fuzz, 'pwn/plugins/fuzz'
    autoload :Git, 'pwn/plugins/git'
    autoload :Github, 'pwn/plugins/github'
    autoload :HackerOne, 'pwn/plugins/hacker_one'
    autoload :IBMAppscan, 'pwn/plugins/ibm_appscan'
    autoload :IPInfo, 'pwn/plugins/ip_info'
    autoload :Jenkins, 'pwn/plugins/jenkins'
    autoload :JSONPathify, 'pwn/plugins/json_pathify'
    autoload :MailAgent, 'pwn/plugins/mail_agent'
    autoload :Metasploit, 'pwn/plugins/metasploit'
    autoload :MSR206, 'pwn/plugins/msr206'
    autoload :NessusCloud, 'pwn/plugins/nessus_cloud'
    autoload :NexposeVulnScan, 'pwn/plugins/nexpose_vuln_scan'
    autoload :NmapIt, 'pwn/plugins/nmap_it'
    autoload :OAuth2, 'pwn/plugins/oauth2'
    autoload :OCR, 'pwn/plugins/ocr'
    autoload :OpenAI, 'pwn/plugins/open_ai'
    autoload :OpenVAS, 'pwn/plugins/openvas'
    autoload :OwaspZap, 'pwn/plugins/owasp_zap'
    autoload :Packet, 'pwn/plugins/packet'
    autoload :PDFParse, 'pwn/plugins/pdf_parse'
    autoload :Pony, 'pwn/plugins/pony'
    autoload :RabbitMQ, 'pwn/plugins/rabbit_mq'
    autoload :RFIDler, 'pwn/plugins/rfidler'
    autoload :Serial, 'pwn/plugins/serial'
    autoload :Shodan, 'pwn/plugins/shodan'
    autoload :SlackClient, 'pwn/plugins/slack_client'
    autoload :Sock, 'pwn/plugins/sock'
    autoload :SonMicroRFID, 'pwn/plugins/son_micro_rfid'
    autoload :Spider, 'pwn/plugins/spider'
    autoload :SSN, 'pwn/plugins/ssn'
    autoload :ThreadPool, 'pwn/plugins/thread_pool'
    autoload :TransparentBrowser, 'pwn/plugins/transparent_browser'
    autoload :TwitterAPI, 'pwn/plugins/twitter_api'
    autoload :URIScheme, 'pwn/plugins/uri_scheme'
    autoload :Vsphere, 'pwn/plugins/vsphere'

    # Display a List of Every PWN Plugin

    public_class_method def self.help
      constants.sort
    end
  end
end
