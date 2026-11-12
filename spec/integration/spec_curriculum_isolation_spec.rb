# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'offline spec curriculum isolation' do
  before do
    @outside = Dir.mktmpdir('pwn-outside-curriculum-')
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', @outside)
    {
      'COOLDOWN_FILE' => 'cooldown.json',
      'MODELS_FILE' => 'models.json',
      'KPI_FILE' => 'curriculum_kpi.jsonl'
    }.each do |name, basename|
      path = File.join(@outside, basename)
      File.write(path, "{\"outside_fixture\":true}\n")
      stub_const("PWN::AI::Agent::Curriculum::#{name}", path)
    end
    stub_const('PWN::AI::Agent::Curriculum::DPO_DIR_CONST', File.join(@outside, 'finetune'))
    @outside_files = Dir.glob(File.join(@outside, '*')).to_h { |path| [path, File.binread(path)] }
  end

  after { FileUtils.remove_entry(@outside) if @outside && Dir.exist?(@outside) }

  context 'with the shared persistence sandbox' do
    include_context 'pwn tmp sandbox'

    it 'keeps cooldown, model and KPI writes away from previously loaded outside paths' do
      curriculum = PWN::AI::Agent::Curriculum
      curriculum.send(:save_cooldown, cooldown: { 'fixture' => { 'fail_nights' => 1 } })
      curriculum.send(:save_models, state: { current: 1 })
      result = curriculum.practice_kpi(results: [{ resolved: true, score: 0.6 }])

      expect(result).to include(practiced: 1, resolved_tonight: 1)
      expect(@outside_files.to_h { |path, _bytes| [path, File.binread(path)] }).to eq(@outside_files)
      expect(JSON.parse(File.read(File.join(@tmp, 'curriculum', 'cooldown.json')))).to eq('fixture' => { 'fail_nights' => 1 })
      expect(JSON.parse(File.read(File.join(@tmp, 'curriculum', 'models.json')))).to eq('current' => 1)
      expect(JSON.parse(File.read(File.join(@tmp, 'curriculum_kpi.jsonl')))).to include('practiced' => 1)
      expect(curriculum::DPO_DIR_CONST).to eq(File.join(@tmp, 'finetune'))
    end
  end
end
