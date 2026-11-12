# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Cron core review regressions' do
  describe 'C2 executes literal script paths' do
    include_context 'pwn tmp sandbox'

    before do
      allow(PWN::Cron).to receive(:sync_one_job)
      allow(PWN::Cron).to receive(:native_execution?).and_return(false)
    end

    it 'preserves the no-script result for an empty path rather than executing cwd' do
      job = PWN::Cron.create(script: '', sync_native: false)
      expect(Open3).not_to receive(:capture2e)
      expect(PWN::Cron.run(id: job[:id])).to include(status: 'success', result: 'No prompt/ruby/script defined')
    end

    it 'executes the checked cwd script instead of a PATH namesake' do
      bin = File.join(@tmp, 'bin')
      cwd = File.join(@tmp, 'working')
      FileUtils.mkdir_p([bin, cwd])
      [[bin, 'path namesake'], [cwd, 'literal cwd script']].each do |dir, text|
        path = File.join(dir, 'relative-fixture')
        File.write(path, "#!/bin/sh\nprintf '#{text}\\n'\n")
        File.chmod(0o700, path)
      end
      previous = ENV.fetch('PATH')
      begin
        ENV['PATH'] = bin
        Dir.chdir(cwd) do
          job = PWN::Cron.create(script: 'relative-fixture', sync_native: false)
          expect(PWN::Cron.run(id: job[:id])).to include(status: 'success', result: "literal cwd script\n")
          expect(PWN::Cron.list[job[:id]][:last_status]).to eq('success')
          File.unlink('relative-fixture')
          expect(PWN::Cron.run(id: job[:id])[:result]).to eq('No prompt/ruby/script defined')
        end
      ensure
        ENV['PATH'] = previous
      end
    end
  end

  describe 'C1 validates every field before calendar matching' do
    let(:now) { Time.local(2026, 6, 1, 5) }

    it 'rejects invalid day fields even when the other restricted day matches', :aggregate_failures do
      ['0 5 99 * 1', '0 5 1 * 99', '0 5 nope * 1', '0 5 1 * 1-0', '0 5 */0 * 1'].each do |schedule|
        expect(PWN::Cron.due?(schedule: schedule, last_run: now - 60, now: now)).to be(false), schedule
      end
    end

    it 'rejects invalid grammar, bounds, ranges and steps anywhere in a list', :aggregate_failures do
      fields = %w[0 5 1 6 1]
      bounds = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]]
      bounds.each_with_index do |(min, max), index|
        bad_atoms = ['nope', '+1', '-1', '0x1', '1_0', '1/2', '*/0', '*/-2', '*/x', '*/1/2', '1-2/0', '1-2/-1', '1-2/1/2', '2-1', (max + 1).to_s, "#{min}-#{max + 1}", "#{min}-#{max + 1}/2"]
        bad_atoms += ['0', '0-2', '0-2/1'] if min.positive?
        bad_fields = bad_atoms.flat_map { |atom| [atom, "#{fields[index]},#{atom}", "#{atom},#{fields[index]}"] }
        bad_fields += ["#{fields[index]},", ",#{fields[index]}", "#{fields[index]},,#{fields[index]}", ',']
        bad_fields.each do |field|
          schedule = fields.dup.tap { |parts| parts[index] = field }.join(' ')
          expect(PWN::Cron.due?(schedule: schedule, last_run: now - 60, now: now)).to be(false), schedule
        end
      end
    end

    it 'retains valid wildcards, lists, steps and restricted day OR matching', :aggregate_failures do
      ['* * * * *', '*/15 1-9/2 * * *', '0,15 5 1 6 2', '0 5 2 6 1', '0 5 */2 6 1', '0 5 * 6 1', '0 5 1 6 *', '0 5 1-31/2 6 2', '*/100 5 * * *'].each do |schedule|
        expect(PWN::Cron.due?(schedule: schedule, last_run: now - 60, now: now)).to be(true), schedule
      end
      ['0 5 * 6 2', '0 5 2 6 *', '0 5 */2 6 2', '0 5 2 6 */2'].each do |schedule|
        expect(PWN::Cron.due?(schedule: schedule, last_run: now - 60, now: now)).to be(false), schedule
      end
    end

    it 'matches Sunday zero and seven in literals, lists and stepped ranges', :aggregate_failures do
      sunday = Time.local(2026, 6, 7, 5)
      %w[0 7 1,7 0-7 5-7 5-7/2 */7].each do |field|
        expect(PWN::Cron.due?(schedule: "0 5 * * #{field}", last_run: sunday - 60, now: sunday)).to be(true), field
      end
    end

    it 'reads zero-padded decimal fields without Ruby integer-prefix semantics' do
      instant = Time.local(2026, 8, 9, 8, 9)
      expect(PWN::Cron.due?(schedule: '09 08 09 08 *', last_run: instant - 60, now: instant)).to be(true)
    end

    it 'retains leap-day catch-up and does not invent impossible dates' do
      expect(PWN::Cron.due?(schedule: '0 5 29 2 *', last_run: Time.local(2024, 2, 1), now: Time.local(2024, 3, 1))).to be(true)
      expect(PWN::Cron.due?(schedule: '0 5 30 2 *', last_run: Time.local(2024, 2, 1), now: Time.local(2024, 3, 1))).to be(false)
    end
  end
end
