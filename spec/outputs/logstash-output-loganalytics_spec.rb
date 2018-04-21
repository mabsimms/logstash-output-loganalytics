# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/logstash-output-loganalytics"
require "logstash/codecs/plain"
require "logstash/event"
require "pp"

describe LogStash::Outputs::LogstashOutputLoganalytics do
  let(:sample_event) { LogStash::Event.new(
    'message' => 'fanastic log entry',
    'source' => 'someapp',
    '@timestamp' => LogStash::Timestamp.now  
  ) }

  let(:output) { LogStash::Outputs::LogstashOutputLoganalytics.new(
    'key' => ENV['OMS_KEY'],
    'workspace' => ENV['OMS_WORKSPACE'],
  )
  }

  before do
    output.register
  end

  describe "receive message" do
    subject { output.receive(sample_event) }

    it "returns a string" do
      expect(subject).to eq("Event received")
    end
  end
end
