require_relative 'ed2k.rb'

MIN_STATUS_CHALLENGE = 0x55AA0000
INV_SERV_DESC_LEN    = 0xF0FF

ServerStatus = Struct.new(:protocol, :opcode, :challenge, :cur_users, :cur_files, :max_users, :soft_files, :hard_files, :udp_flags, :low_id, :obf_udp_port, :obf_tcp_port, :udp_key)
ServerDesc = Struct.new(:name, :description, :version, :dynamic_ip, :aux_ports, :other_tags)

module Logger
  DEFAULT_CAPACITY = 500
  LogLine = Struct.new(:time, :name, :text)

  def init_log(name, capacity = nil)
    @log_name = name
    @log_capacity = capacity || DEFAULT_CAPACITY
    @log_lines = []
  end

  def log(text)
    line = LogLine.new(Time.now, @log_name, text)
    @log_lines << line
    @log_lines.shift(@log_lines.size - @log_capacity) if @log_lines.size > @log_capacity
    print("\e[s\r\e[1L#{format(line)}\e[u\n")
  end

  private

  def format(l)
    "[%s] (%s) %s" % [l.time.strftime("%Y-%m-%d %H:%M:%S.%L"), l.name, l.text]
  end
end

module Stats
  def init_stats
    @stats = { sent: 0, received: 0 }
  end

  def get_sent
    @stats[:sent]
  end

  def get_received
    @stats[:received]
  end

  def add_sent(n)
    @stats[:sent] += n
  end

  def add_received(n)
    @stats[:received] += n
  end
end

class RC4
  def initialize(key)
    @q1, @q2 = 0, 0
    @state = (0...256).to_a
    key_length = key.length
    while @q1 < 256
      @q2 = (@q2 + @state[@q1] + key.getbyte(@q1 % key_length)) % 256
      @state[@q1], @state[@q2] = @state[@q2], @state[@q1]
      @q1 += 1
    end
    @q1, @q2 = 0, 0
  end

  def encrypt!(text)
    text.force_encoding(Encoding::BINARY)
    index = 0
    while index < text.bytesize
      @q1 = (@q1 + 1) % 256
      @q2 = (@q2 + @state[@q1]) % 256
      @state[@q1], @state[@q2] = @state[@q2], @state[@q1]
      text.setbyte(index, text.getbyte(index) ^ @state[(@state[@q1] + @state[@q2]) % 256])
      index += 1
    end
    text
  end

  def encrypt(text)
    encrypt!(text.dup)
  end

  alias_method :decrypt!, :encrypt!
  alias_method :decrypt, :encrypt
end

class Ed2kUDPSocket
  include Stats
  include Logger

  READ_RATE         = 10
  MAX_DATAGRAM_SIZE = 1 << 16

  def initialize
    @socket = UDPSocket.new
    @socket.bind('0.0.0.0', 0)
    @thread = Thread.new do
      loop do
        begin
          readable, = IO.select([@socket], nil, nil, 0)
          read() if readable
        rescue => e
          log("Error while reading: #{e.class}: #{e.message}")
        end
        break if !@running
        sleep(1.0 / READ_RATE)
      end
    end
    @running = true
    init_log("ed2k UDP socket")
    init_stats()
  end

  def stop(force = false)
    @running = false
    sleep(1) while @thread.status unless force
    @thread.kill
    @socket.close
  end

  def write(addr, packet)
    @socket.send(packet, 0, addr.ip_address, addr.ip_port)
    log("Sent #{packet.size} bytes to #{addr.inspect_sockaddr}")
    add_sent(packet.size)
  end

  def read
    recsize = 0
    data, sender = @socket.recvfrom(MAX_DATAGRAM_SIZE) # fetch exactly one datagram
    recsize = data.size
    return if recsize <= 0
    add_received(recsize)
    ip = sender[3]
    port = sender[1]
    server = Server.server(ip: ip)
    if !server
      log("Received #{recsize} bytes from #{ip}:#{port}, discarded")
      return recsize
    end
    log("Received #{recsize} bytes from #{server.name}")
    server.receive(data)
    recsize
  end
end

class Server
  include Stats
  include Logger

  attr_reader :name

  @@servers = {}

  def self.server(name: nil, ip: nil)
    return unless name || ip
    @@servers[ip] || @@servers.find{ |k, v| v.name == name }&.last
  end

  def initialize(name, ip, port)
    # Properties
    @ip            = ip
    @port_tcp      = port
    @port_udp      = @port_tcp + 4
    @port_tcp_obf  = @port_tcp
    @port_udp_obf  = @port_tcp + 12
    @name          = name
    @description   = nil
    @version       = nil # String, e.g. "17.15"
    @flags_udp     = nil # uint32
    @udp_key       = nil # uint32

    # State
    @packets         = Queue.new
    @challenge_stats = nil
    @key_pending     = false

    # Config
    @obfuscate_tcp = false
    @obfuscate_udp = false

    # Init
    init_log(@name)
    init_stats()
    @@servers[@ip] = self
  end

  def receive(packet)
    add_received(packet.size)
    return if packet.size < 2

    # Try to decrypt packet in place
    was_encrypted = false
    if key() && (@obfuscate_udp || packet[0].ord != OP_EDONKEYPROT)
      log("Received unexpected encrypted UDP packet, decrypting anyway") if !@obfuscate_udp
      case status = decrypt!(packet)
      when nil
        log("Failed to decrypt UDP packet of size #{packet.size}, discarding")
        return
      when false
        log("Expected encrypted UDP packet, received raw one")
      when true
        log("Decrypted UDP packet")
        was_encrypted = true
      else
        log("Decryption returned unexpected value #{status.inspect}, discarded")
        return
      end
    end

    # Verify packet header
    protocol, opcode = packet.unpack('C2')
    if protocol != OP_EDONKEYPROT
      log("Unknown protocol in %s UDP packet" % [was_encrypted ? 'decrypted' : 'raw'])
      return
    end

    # Process packet
    case opcode
    when OP_GLOBSERVSTATRES
      @packets << parse_stats(packet)
    when OP_SERVER_DESC_RES
      @packets << parse_description(packet)
    else
      log("Received unknown packet from %s: prot %#2x, op %#2x" % [@name, protocol, opcode])
      @packets << packet
    end
  end

  # Server capabilities sent as UDP flags in the status response
  def supports_extended_sources()  !!@flags && @flags & SRV_UDPFLG_EXT_GETSOURCES  > 0 end
  def supports_extended_searches() !!@flags && @flags & SRV_UDPFLG_EXT_GETFILES    > 0 end
  def supports_new_tags()          !!@flags && @flags & SRV_UDPFLG_NEWTAGS         > 0 end
  def supports_unicode()           !!@flags && @flags & SRV_UDPFLG_UNICODE         > 0 end
  def supports_new_getsources()    !!@flags && @flags & SRV_UDPFLG_EXT_GETSOURCES2 > 0 end
  def supports_large_files()       !!@flags && @flags & SRV_UDPFLG_LARGEFILES      > 0 end
  def supports_udp_obfuscation()   !!@flags && @flags & SRV_UDPFLG_UDPOBFUSCATION  > 0 end
  def supports_tcp_obfuscation()   !!@flags && @flags & SRV_UDPFLG_TCPOBFUSCATION  > 0 end

  # Crypt pings ask for the obfuscation information (ports + key) as well
  # They are never obfuscated, because we lack that info yet,
  # but the response IS obfuscated, and the key is the challenge
  def request_stats(crypt = false, obf: false)
    obf = false if crypt
    @key_pending = crypt
    @challenge_stats = crypt ? rand(1 << 32) : MIN_STATUS_CHALLENGE + rand(1 << 16)
    packet = [OP_EDONKEYPROT, OP_GLOBSERVSTATREQ, @challenge_stats].pack('CCL<')
    packet << rand(16).times.map{ rand(256) }.pack('C*') if crypt
    obf = encrypt!(packet) if obf
    send_udp(packet, obf: obf || crypt)
    log("Sent UDP status request with challenge %#2x" % [@challenge_stats])
  end

  # New packet (eserver 16.45+) adds a challenge, returns more fields
  def request_description(old = false)
    packet = [OP_EDONKEYPROT, OP_SERVER_DESC_REQ].pack('CC')
    if !old
      @challenge_desc = (rand(1 << 16) << 16) + INV_SERV_DESC_LEN
      packet << [@challenge_desc].pack('L<')
    end
    send_udp(packet)
  end

  def pop
    @packets.pop(true)
  rescue ThreadError
    nil
  end

  private

  def send_udp(packet, obf: @obfuscate_udp)
    $socket.write(Addrinfo.udp(@ip, obf ? @port_udp_obf : @port_udp), packet)
    add_sent(packet.size)
  end

  def key
    @key_pending && @challenge_stats || @udp_key
  end

  def build_key(random, incoming)
    return unless key = key()
    magic = incoming ? 0xA5 : 0x6B
    seed = [key, magic, random].pack('L<CS<')
    Digest::MD5.digest(seed)
  end

  def encrypt!(packet)
    return false unless key()
    random = rand(1 << 16)
    key = build_key(random, false)
    rc4 = RC4.new(key)
    protocol = OP_EDONKEYPROT
    protocol = rand(256) while protocol == OP_EDONKEYPROT
    packet.prepend([0x13EF24D5, 0].pack('L<C'))
    rc4.encrypt!(packet)
    packet.prepend([protocol, random].pack('CS<'))
    true
  end

  # Returns 'false' if it didn't decrypt, 'true' if it did, and 'nil' if it failed
  def decrypt!(packet)
    return false if packet.size < 8 || !key() # crypt header doesn't fit
    protocol, random = packet.unpack('CS<')
    return false if protocol == OP_EDONKEYPROT # unencrypted
    key = build_key(random, true)
    rc4 = RC4.new(key)
    packet.slice!(0, 3)
    rc4.decrypt!(packet)
    magic, pad_len = packet.unpack('L<C')
    return if magic != 0x13EF24D5 # invalid magic number
    pad_len &= 0xF
    return if packet.size <= 5 + pad_len # padding doesn't fit
    packet.slice!(0, 5 + pad_len)
    true
  end

  def parse_stats(data)
    packet = ServerStatus.new(*data.unpack('CCL<8S<2L<'))
    if !@challenge_stats
      log("Received unrequested UDP status response, ignored")
      return
    elsif packet.challenge != @challenge_stats
      log("Received UDP status response with incorrect challenge, ignored")
      return
    else
      log("Received UDP status response: #{packet.cur_users} users, #{packet.cur_files} files.")
    end
    @key_pending = false
    @challenge_stats = nil
    @flags_udp = packet.udp_flags if packet.udp_flags
    @port_tcp_obf = packet.obf_tcp_port if packet.obf_tcp_port
    @port_udp_obf = packet.obf_udp_port if packet.obf_udp_port
    @udp_key = packet.udp_key if packet.udp_key
    packet
  end

  # Old packet only contains name and description, new packet returns the challenge and a tag list
  def parse_description(data)
    packet = ServerDesc.new

    # Corrupt packet
    if data.size < 4
      log("Received corrupt server description")
      return
    end

    # Old-style packet
    if data.size < 8 || data.unpack1('S<') != INV_SERV_DESC_LEN
      name_len = data.unpack1('S<')
      return if data.size < 4 + name_len
      packet.name = @name = data[2, name_len]
      desc_len = data.unpack1('S<', offset: 2 + name_len)
      return if data.size < 4 + name_len + desc_len
      packet.description = @description = data[4 + name_len, desc_len]
      log("Received old server description: name = #{@name}, description = #{@description}")
      padding = data.size - 4 - name_len - desc_len
      log("Received #{padding} extra bytes in old server description") if padding > 0
      return packet
    end

    # Unrequested packet
    if !@challenge_desc
      log("Received unrequested new server description, ignored")
      return
    elsif data.unpack1('L<') != @challenge_desc
      log("Received new server description with incorrect challenge, ignored")
      return
    end

    # New-style packet
    @challenge_desc = nil
    fields = {}
    tags = Tag::read(data[4..])
    packet.other_tags = tags.each do |name, value|
      case name
      when ST_SERVERNAME
        fields['name'] = packet.name = @name = value
      when ST_DESCRIPTION
        fields['description'] = packet.description = @description = value
      when ST_VERSION
        value = "%d.%02d" % [value >> 16, value & 0xFFFF] if value.is_a?(Integer)
        fields['version'] = packet.version = @version = value
      when ST_DYNIP
        fields['dynamic IP'] = packet.dynamic_ip = value
      when ST_AUXPORTSLIST
        fields['aux ports list'] = packet.aux_ports = value.split(',').map(&:to_i)
      else
        log("Received unexpected tag in new server description: #{name} = #{value}")
        next
      end
      tags.delete(name)
    end
    fields = fields.map{ |name, value| "#{name} = #{value}" }.join(', ')
    log("Received new server description: #{fields} and #{packet.other_tags.size} unknown tags")
    packet
  end
end

# Fill in config
Server.new('eMule Security',   '45.82.80.155',     5687)
Server.new('eMule Sunrise',    '176.123.5.89',     4725)
Server.new('Sharing-Devils 2', '85.121.5.137',     4232)
Server.new('Astra-3',          '213.252.245.239', 43333)
Server.new('Hydra',            '141.227.139.101',  4235)
Server.new('Ed2k-rust',        '45.87.41.16',      6262)

# Bootstrap app
$socket = Ed2kUDPSocket.new
