# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'SAST rule runtime regressions' do
  around do |example|
    Dir.mktmpdir('pwn-sast-rules-') do |dir|
      @source_dir = dir
      example.run
    end
  end

  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    allow(PWN::AI::Agent::SAST).to receive(:analyze).and_return(nil)
  end

  fixtures = {
    AMQPConnectAsGuest: ['.txt', 'amqp guest'],
    ApacheFileSystemUtilAPI: ['.java', 'import org.apache.commons.io.FileSystemUtils'],
    AWS: ['.txt', 'access_key = fixture'],
    BannedFunctionCallsC: ['.c', 'strcpy(dest, src);'],
    Base64: ['.txt', 'Base64.decode(data)'],
    BeefHook: ['.txt', 'hook.js'],
    CmdExecutionGoLang: ['.go', 'exec.Command("fixture")'],
    CmdExecutionJava: ['.java', 'new ProcessBuilder("fixture")'],
    CmdExecutionPython: ['.py', 'os.system("fixture")'],
    CmdExecutionRuby: ['.rb', 'eval("fixture")'],
    CmdExecutionScala: ['.scala', 'Process("fixture")'],
    CSRF: ['.txt', 'csrf_token'],
    DeserialJava: ['.java', 'stream.readObject()'],
    Emoticon: ['.txt', ':-)'],
    Eval: ['.txt', 'eval("fixture")'],
    Factory: ['.java', 'DocumentBuilderFactory.newInstance()'],
    HTTPAuthorizationHeader: ['.txt', 'authorization = fixture'],
    InnerHTML: ['.txt', 'node.innerHTML = input'],
    Keystore: ['.txt', 'keystore'],
    LocalStorage: ['.txt', 'localStorage.setItem("fixture", data)'],
    LocationHash: ['.txt', 'location.hash'],
    Log4J: ['.java', 'import org.apache.log4j.Logger'],
    Logger: ['.txt', 'logger.info(password)'],
    MD5: ['.txt', 'md5'],
    OuterHTML: ['.txt', 'node.outerHTML = input'],
    PaddingOracle: ['.txt', 'AES/CBC/PKCS5Padding'],
    Password: ['.txt', 'password = fixture'],
    PHPInputMechanisms: ['.php', '$_GET["fixture"]'],
    PHPTypeJuggling: ['.php', '$a == $b'],
    Port: ['.txt', 'localhost:8080'],
    PostMessage: ['.txt', 'postMessage(data)'],
    PrivateKey: ['.txt', 'PRIVATE KEY'],
    Redirect: ['.txt', 'redirect_uri = input'],
    ReDOS: ['.txt', '(a+)+'],
    Shell: ['.txt', '/bin/sh'],
    Signature: ['.txt', 'Signature'],
    SQL: ['.txt', 'SELECT name FROM users'],
    SSL: ['.txt', 'trustAll'],
    Sudo: ['.txt', 'sudo'],
    TaskTag: ['.txt', '# TODO: fixture'],
    ThrowErrors: ['.txt', 'raise "fixture"'],
    Token: ['.txt', 'oauth'],
    TypeScriptTypeJuggling: ['.ts', 'a == b'],
    UseAfterFree: ['.c', 'free(pointer);'],
    Version: ['.txt', 'version = "1.0"'],
    WindowLocationHash: ['.txt', 'window.location.hash']
  }

  fixtures.each do |name, (extension, source)|
    it "runs #{name} through the real scanner and returns its numbered match" do
      File.write(File.join(@source_dir, "sample#{extension}"), "#{source}\n")
      result = PWN::SAST.const_get(name).scan(dir_path: @source_dir)
      expect(result.length).to eq(1)
      expect(result.first[:security_references][:sast_module]).to eq(PWN::SAST.const_get(name))
      expect(result.first[:line_no_and_contents].first).to include(line_no: '1', contents: "#{source}\n", ai_analysis: 'N/A')
    end
  end
end
