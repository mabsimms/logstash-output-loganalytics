# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "time"
require "base64"
require "openssl"
require "uri"
require "net/https"
require "json"

# An logstash-output-loganalytics output that does nothing.
class LogStash::Outputs::LogstashOutputLoganalytics < LogStash::Outputs::Base
  config_name "logstash-output-loganalytics"

  # TODO - workspace 
  config :workspace, :validate => :string, :required => true
  # TODO - key
  config :key, :validate => :string, :required => true
  # TODO - timestamp field
  config :timestamp_field, :validate => :string, :default => "@timestamp"

  public
  def register
  end # def register

  public
  def receive(event)
    send_data(workspace, key, event.to_json, "test")
    return "Event received"
  end # def event

  def send_data(customer_id, shared_key, content, log_name)        
    current_time = Time.now.utc
    signature = build_signature(
      shared_key, current_time, content.length, 
      "POST", "application/json", "/api/logs")
    publish_data(log_name, signature, current_time, content)
  end

  def publish_data(log_name, signature, time, json)
    url = "https://#{workspace}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    uri = URI url

    rfc1123date = time.utc.strftime("%a, %d %b %Y %H:%M:%S GMT")

    response = Net::HTTP.start(uri.hostname, uri.port, 
      :use_ssl => uri.scheme == 'https') do |http|

      req = Net::HTTP::Post.new(uri.to_s)
      req.body = json.to_s
      
      # Signature and headers
      req['Content-Type'] = 'application/json'
      req['Log-Type'] = log_name
      req['Authorization'] = signature
      req['x-ms-date'] = rfc1123date

      @logger.debug "Publishing record of length #{req.body.length} to OMS workspace #{workspace}"    
      http.request(req)          
    end

    case response 
    when Net::HTTPSuccess
      @logger.debug "Successfully published record of length #{json.length} to OMS workspace #{workspace}"                 
    else
      # TODO - throw error
      @logger.warn "Could not publish record of length #{json.length} to OMS workspace #{workspace} because #{response}"
    end 
    response
  end

  def build_signature(shared_key, date, content_length, method, content_type, resource)
    rfc1123date = date.utc.strftime("%a, %d %b %Y %H:%M:%S GMT")
    string_to_hash = "#{method}\n#{content_length}\n#{content_type}\nx-ms-date:#{rfc1123date}\n#{resource}"        
    decoded_key = Base64.decode64(shared_key)
    secure_hash = OpenSSL::HMAC.digest('SHA256', decoded_key, string_to_hash)
          
    encoded_hash = Base64.encode64(secure_hash).strip()
    authorization = "SharedKey #{workspace}:#{encoded_hash}"

    return authorization
  end    

end # class LogStash::Outputs::LogstashOutputLoganalytics
