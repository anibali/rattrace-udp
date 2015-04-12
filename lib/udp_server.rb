#!/usr/bin/env ruby
#
# This is a simple UDP server which forwards raw incoming messages from the
# rat traps to the web server.
#
# Code to simulate a UDP packet send:
#
#     require 'socket'
#     udp = UDPSocket.new
#     report = [1, 12345, "Blah"].pack("S<S<C*")
#     udp.send report, 0, "127.0.0.1", 9252

# Allow us to require other files in lib/
$:.unshift File.expand_path("../", __FILE__) if __FILE__ == $0

require 'socket'
require 'net/http'
require 'open-uri'
require 'yaml'
require 'json'
require 'base64'

def get_in(hash, keys)
  object = hash
  keys.each do |key|
    object = object.fetch(key)
  end
  return object
end

def log(tag, msg)
  first_line = true
  msg.to_s.each_line do |line|
    puts("%-7s %s" % [first_line ? "[#{tag}]" : ">", line])
    first_line = false
  end
end

def log_info(msg)
  log("INFO", msg)
end

def log_error(msg)
  log("ERROR", msg)
end

class UdpServer
  def initialize(config)
    @udp = UDPSocket.new
    @udp.bind(Socket::INADDR_ANY, get_in(config, %w[incoming port]))

    @http = Net::HTTP.new(
      get_in(config, %w[outgoing host]),
      get_in(config, %w[outgoing port]))

    @endpoint = get_in(config, %w[outgoing endpoint])
    @max_message_length = get_in(config, %w[incoming max-message-length])

    @auth_username = %w[outgoing username]
    @auth_password = %w[outgoing password]
  end

  def process_message(msg)
    # TODO: We probably want to do some simple processing on the message here
    # to reduce load on the web server

    # TODO: Verify the source of the message. Encryption?

    unpacked = msg.unpack("S<S<C*")
    version = unpacked[0]
    trap_id = unpacked[1]
    rest = unpacked[2..-1].pack("C*")

    json = {
      original_message: Base64.encode64(msg).strip,
      protocol_version: version,
      trap_id: unpacked[1]
    }

    log_info("Sending JSON: #{json.to_json}")

    request = Net::HTTP::Post.new(@endpoint, initheader = {'Content-Type' => 'application/json'})
    request.basic_auth(@auth_username, @auth_password)
    request.body = json.to_json

    begin
      response = @http.request(request)
    rescue Errno::ECONNREFUSED
      log_error "Destination server unavailable"
      return
    end

    if response.code != "200"
      log_error "Server returned status code #{response.code}"
      return
    end

    log_info "JSON successfully sent to server"
  end

  def run
    loop do
      # Receive UDP message
      msg, sender_info = *@udp.recvfrom(@max_message_length)
      log_info "Received message: #{msg.inspect}"

      process_message(msg)
    end
  end
end

def main()
  config_file = File.join(File.expand_path("../../", __FILE__), "config.yml")
  config = YAML.load(File.read(config_file))

  server = UdpServer.new(config)
  server.run
end

# Entry point
if __FILE__ == $0
  main()
end
