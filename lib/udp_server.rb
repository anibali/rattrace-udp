#!/usr/bin/env ruby
#
# This is a simple UDP server which forwards raw incoming messages from the
# rat traps to the web server.
#
# Code to simulate a UDP packet send:
#
#     require 'socket'
#     udp = UDPSocket.new
#     data = [
#       *"RATR".unpack("C*"), # Identifier
#       1,                    # Protocol version
#       1234,                 # Trap ID
#       100,                  # Send time
#       1,                    # Number of report chunks
#       1,                    # First chunk type (battery level)
#       50,                   # First chunk timestamp
#       2,                    # First chunk length (2 bytes)
#       2**16 - 1,            # Battery level (corresponds to 100%)
#     ]
#     report = data.pack("C4 C I< I< C   C I< C S<")
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
  CHUNK_TYPES_V1 = {
    1 => :battery_level
  }

  def initialize(config)
    @udp = UDPSocket.new
    @udp.bind(Socket::INADDR_ANY, get_in(config, %w[incoming port]))

    @http = Net::HTTP.new(
      get_in(config, %w[outgoing host]),
      get_in(config, %w[outgoing port]))

    @endpoint = get_in(config, %w[outgoing endpoint])
    @max_message_length = get_in(config, %w[incoming max-message-length])

    @auth_username = get_in(config, %w[outgoing username])
    @auth_password = get_in(config, %w[outgoing password])
  end

  def process_message(msg)
    # TODO: Verify the source of the message. Encryption?

    ptr = 0

    if msg[ptr...ptr + 4] != "RATR"
      log_error "Bad packet identifier received"
      return
    end

    ptr += 4

    header = msg[ptr...ptr + 10].unpack("C I< I< C")
    protocol_version, trap_id, send_time, n_report_chunks = *header

    ptr += 10

    chunks = []

    n_report_chunks.times do
      chunk_header = msg[ptr...ptr + 6].unpack("C I< C")
      chunk_type, chunk_time, chunk_length = *chunk_header
      ptr += 6

      type = CHUNK_TYPES_V1[chunk_type]

      unless type.nil?
        chunk = {
          type: type,
          timestamp: chunk_time
        }

        case type
        when :battery_level
          chunk_data = msg[ptr...ptr + 2].unpack("S<")
          chunk[:battery_charge] = chunk_data[0].to_f / (2**16 - 1)
        else
          log_error "Encountered unknown report chunk type"
        end

        chunks << chunk
      end

      ptr += chunk_length
    end

    json = {
      original_message: Base64.encode64(msg).strip,
      protocol_version: protocol_version,
      trap_id: trap_id,
      chunks: chunks
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
