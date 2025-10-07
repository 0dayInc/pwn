# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP static code analysis
  # modules into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module SAST
    # Zero False Negative SAST Modules
    autoload :ApacheFileSystemUtilAPI, 'pwn/sast/apache_file_system_util_api'
    autoload :AMQPConnectAsGuest, 'pwn/sast/amqp_connect_as_guest'
    autoload :AWS, 'pwn/sast/aws'
    autoload :BannedFunctionCallsC, 'pwn/sast/banned_function_calls_c'
    autoload :Base64, 'pwn/sast/base64'
    autoload :BeefHook, 'pwn/sast/beef_hook'
    autoload :CmdExecutionJava, 'pwn/sast/cmd_execution_java'
    autoload :CmdExecutionPython, 'pwn/sast/cmd_execution_python'
    autoload :CmdExecutionRuby, 'pwn/sast/cmd_execution_ruby'
    autoload :CmdExecutionScala, 'pwn/sast/cmd_execution_scala'
    autoload :CSRF, 'pwn/sast/csrf'
    autoload :DeserialJava, 'pwn/sast/deserial_java'
    autoload :Emoticon, 'pwn/sast/emoticon'
    autoload :Eval, 'pwn/sast/eval'
    autoload :Factory, 'pwn/sast/factory'
    autoload :HTTPAuthorizationHeader, 'pwn/sast/http_authorization_header'
    autoload :InnerHTML, 'pwn/sast/inner_html'
    autoload :Keystore, 'pwn/sast/keystore'
    autoload :LocalStorage, 'pwn/sast/local_storage'
    autoload :LocationHash, 'pwn/sast/location_hash'
    autoload :Log4J, 'pwn/sast/log4j'
    autoload :Logger, 'pwn/sast/logger'
    autoload :MD5, 'pwn/sast/md5'
    autoload :OuterHTML, 'pwn/sast/outer_html'
    autoload :PaddingOracle, 'pwn/sast/padding_oracle'
    autoload :Password, 'pwn/sast/password'
    autoload :PHPInputMechanisms, 'pwn/sast/php_input_mechanisms'
    autoload :PHPTypeJuggling, 'pwn/sast/php_type_juggling'
    autoload :PomVersion, 'pwn/sast/pom_version'
    autoload :Port, 'pwn/sast/port'
    autoload :PostMessage, 'pwn/sast/post_message'
    autoload :PrivateKey, 'pwn/sast/private_key'
    autoload :Redirect, 'pwn/sast/redirect'
    autoload :ReDOS, 'pwn/sast/redos'
    autoload :Shell, 'pwn/sast/shell'
    autoload :Signature, 'pwn/sast/signature'
    autoload :SQL, 'pwn/sast/sql'
    autoload :SSL, 'pwn/sast/ssl'
    autoload :Sudo, 'pwn/sast/sudo'
    autoload :TaskTag, 'pwn/sast/task_tag'

    # This module executes all the other SAST modules
    autoload :TestCaseEngine, 'pwn/sast/test_case_engine'

    autoload :ThrowErrors, 'pwn/sast/throw_errors'
    autoload :Token, 'pwn/sast/token'
    autoload :TypeScriptTypeJuggling, 'pwn/sast/type_script_type_juggling'
    autoload :Version, 'pwn/sast/version'
    autoload :WindowLocationHash, 'pwn/sast/window_location_hash'

    # Display a List of Every PWN::SAST Module

    public_class_method def self.help
      constants.sort
    end
  end
end
