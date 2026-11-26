# frozen_string_literal: true

# Query the kernel, independently of the sandbox under test. The VERSION flag
# creates no ruleset and changes no permissions. Do not skip on implementation
# failures: once the kernel reports ABI 3+, the real boundary must work.
module PwnSpecLandlock
  def self.unavailable_reason
    required = 'NotImplementedError: Linux Landlock ABI 3 or newer is required'
    return required unless RUBY_PLATFORM.match?(/\A(?:x86_64|aarch64).*linux/)

    abi = Kernel.syscall(444, 0, 0, 1) # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    required if abi < 3
  rescue Errno::ENOSYS, Errno::EOPNOTSUPP, Errno::EPERM, Errno::EACCES => e
    "#{e.class}: #{e.message}"
  end
end

RSpec.configure do |config|
  config.before(:each, :requires_landlock) do
    reason = PwnSpecLandlock.unavailable_reason
    skip "requires Linux Landlock ABI 3+ (#{reason})" if reason
  end
end
