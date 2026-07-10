# frozen_string_literal: true

require 'spec_helper'

describe PWN::Setup do
  it 'should display information for authors' do
    authors_response = PWN::Setup
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Setup
    expect(help_response).to respond_to :help
  end

  it 'exposes the capability data tables' do
    expect(PWN::Setup::NATIVE_GEMS).to be_a(Hash)
    expect(PWN::Setup::TOOLCHAIN).to be_a(Hash)
    expect(PWN::Setup::PROFILES).to be_a(Hash)
    expect(PWN::Setup::PROFILES).to have_key(:full)
  end

  it 'detects a package manager without raising' do
    pm = PWN::Setup.pkg_manager
    expect(pm).to be_a(Hash)
    expect(pm).to have_key(:key)
  end
end
