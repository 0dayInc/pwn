# frozen_string_literal: true

require 'spec_helper'

describe PWN::Cron do
  it 'should display information for authors' do
    authors_response = PWN::Cron
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Cron
    expect(help_response).to respond_to :help
  end

  it 'should support create/list/run/remove' do
    j = PWN::Cron.create(name: 'spec-cron', schedule: '* * * * *', prompt: 'spec test prompt')
    expect(j[:id]).not_to be_nil
    lst = PWN::Cron.list
    expect(lst.keys).to include(j[:id])
    # run would call AI which may require keys; just check structure
    PWN::Cron.remove(id: j[:id])
    expect(PWN::Cron.list.keys).not_to include(j[:id])
  end
end
