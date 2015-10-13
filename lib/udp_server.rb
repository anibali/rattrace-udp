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
#     report = data.pack("C4 C L< L< C   C L< C S<")
#     udp.send report, 0, "127.0.0.1", 9252

# Allow us to require other files in lib/
$:.unshift File.expand_path("../", __FILE__) if __FILE__ == $0

require 'socket'
require 'net/http'
require 'open-uri'
require 'yaml'
require 'json'
require 'base64'
require 'erubis'

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
    1 => :battery_level,
    2 => :bait_level,
    3 => :trap_opened
  }

  def initialize(config)
    @udp = UDPSocket.new
    @udp.bind(Socket::INADDR_ANY, get_in(config, %w[incoming port]))

    log_info "RatTrace UDP server started"

    @http = Net::HTTP.new(
      get_in(config, %w[outgoing host]),
      get_in(config, %w[outgoing port]))

    @endpoint = get_in(config, %w[outgoing endpoint])
    @max_message_length = get_in(config, %w[incoming max-message-length])

    @auth_username = get_in(config, %w[outgoing username])
    @auth_password = get_in(config, %w[outgoing password])
  end

  def process_ratr_request(msg, sender_info)
    ptr = 0

    if msg[ptr...ptr + 4] != "RATR"
      log_error "Bad packet identifier received"
      return
    end

    ptr += 4

    header = msg[ptr...ptr + 10].unpack("C L< L< C")
    protocol_version, trap_id, send_time, n_report_chunks = *header

    ptr += 10

    chunks = []

    n_report_chunks.times do
      chunk_header = msg[ptr...ptr + 6].unpack("C L< C")
      chunk_type, chunk_time, chunk_length = *chunk_header
      ptr += 6

      type = CHUNK_TYPES_V1[chunk_type]

      chunk = {
        chunk_type: chunk_type,
        timestamp: chunk_time,
        data: {}
      }

      case type
      when :battery_level
        battery_charge = *msg[ptr...ptr + 2].unpack("S<")
        chunk[:data][:battery_charge] = battery_charge
      when :bait_level
        bait_id, bait_level = *msg[ptr...ptr + 4].unpack("S<S<")
        chunk[:data][:bait_id] = bait_id
        chunk[:data][:bait_level] = bait_level
      when :trap_opened
        opened_at = *msg[ptr...ptr + 4].unpack("L<")
        chunk[:data][:opened_at] = opened_at
      else
        log_error "Encountered unknown report chunk type"
      end

      chunks << chunk

      ptr += chunk_length
    end

    json = {
      original_message: Base64.encode64(msg).strip,
      protocol_version: protocol_version,
      trap_id: trap_id,
      send_time: send_time,
      chunks: chunks
    }

    log_info "Sending JSON:\n#{JSON.pretty_generate(json)}"

    request = Net::HTTP::Post.new(@endpoint, initheader = {'Content-Type' => 'application/json'})
    request.basic_auth(@auth_username, @auth_password)
    request.body = json.to_json

    begin
      response = @http.request(request)
    rescue Errno::ECONNREFUSED
      log_error "Unable to connect to #{@http.address}:#{@http.port}"
      return
    end

    if response.code != "200"
      log_error "Server returned status code #{response.code}"
      return
    end

    log_info "JSON successfully sent to server"
  end

  def process_time_request(msg, sender_info)
    seconds_since_2000 = (Time.now - Time.new(2000, 1, 1)).to_i

    @udp.send seconds_since_2000.to_s, 0, sender_info[3], sender_info[1]
  end

  def process_request(msg, sender_info)
    log_info "Received message: #{msg.inspect}"

    # TODO: Verify the source of the message. Encryption? Hash?

    case msg[0..3]
    when 'RATR'
      process_ratr_request(msg, sender_info)
    when 'TIME'
      process_time_request(msg, sender_info)
    else
      log_error "Unknown request tag: #{msg[0..3]}"
    end
  end

  def run
    loop do
      # Receive UDP message
      msg, sender_info = *@udp.recvfrom(@max_message_length)

      process_request(msg, sender_info)
    end
  end
end

def main
  config_file = File.join(File.expand_path("../../", __FILE__), "config.yml")
  config_template = Erubis::Eruby.new(File.read(config_file))
  config = YAML.load(config_template.result)

  server = UdpServer.new(config)
  server.run
end

# Entry point
if __FILE__ == $0
  main()
end
