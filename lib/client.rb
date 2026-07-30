module ED2K
  # Clients are the nodes in the ed2k network that actually host the files and share them betweem each other. They are
  # hosts running client programs such as
  # [eDonkey2000](https://web.archive.org/web/20060827140711/http://www.edonkey.com/index.html),
  # [eMule](https://www.emule-project.com/),
  # [MLDonkey](https://github.com/ygrek/mldonkey),
  # [aMule](https://github.com/amule-project/amule),
  # [lPhant](https://web.archive.org/web/20080206023028/http://www.lphant.com/) or
  # [Shareaza](https://shareaza.sourceforge.net/), among others.
  # eMule extended the original protocol in many ways, particularly in client-to-client communication. Clients compatible
  # with the eMule extended protocol are known as **eMule compatible**.
  #
  # Clients connect to one or more servers in order to publish the files they are sharing, and the server will
  # index both the clients and the files to interconnect them and provide search functionalities, among others.
  # See {Server} for more info on servers.
  #
  # In order for a client to establish a connection with another client the receiver must be reachable, i.e., have the ports
  # open and a socket listening on them. In this scenario the server will assign you a **High ID** which will be your IPv4
  # address, otherwise you'll be assigned a **Low ID** (a random 3-byte integer). A low ID client can connect to a high ID
  # client, and a high ID client can connect to a low ID client *in the same server* thanks to a callback mechanism that is
  # routed through the server. Two low ID clients cannot connect to each other.
  #
  # Apart from sharing files, clients can exchange a wide variety of messages between themselves, specially in the
  # eMule extended protocol. A notable example is [Source Exchange](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=137&rm=show_topic),
  # which enables a client to query other clients for additional sources for a given file being downloaded. Another
  # example is the ability to query for one's [Queue Ranking](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=102&rm=show_topic),
  # i.e., the position of our client in another client's upload queue. The extended protocol also introduced UDP requests
  # between clients for periodic queries, such as file reasks. Note that frequent queries like this can result in
  # getting [blacklisted](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=136).
  class Client
    include Connection

    # The ID of the client is an integer that identifies the client within a server. If it's 4 bytes then it corresponds
    # to its IPv4 address, and this should indicate that the client is reachable and we can establish a connection
    # directly. If it's at most 3 bytes then it's a random identifier assigned by the server, and we can only connect
    # to them by requesting a callback through the server.
    attr_reader :id

    # IP address of the server the client is currently connected to, if any. Advertised in {Packet::Hello}.
    # @return [String,nil]
    attr_reader :server_ip

    # Listening TCP port of the server the client is currently connected to, if any. Advertised in {Packet::Hello}.
    # @return [Integer,nil]
    attr_reader :server_port

    # The server the client is currently connected to, only if we know it. Advertised in {Packet::Hello}.
    # @return [Server]
    attr_reader :server

    # The client's 16-byte MD4 hash that identifies them in the ed2k network. Should be unique, but it's generated randomly
    # by the client software (e.g. eMule) on first launch, so there's collision risk. Advertised in {Packet::Hello}.
    # @return [String,nil]
    attr_reader :hash

    # The client's nickname in the ed2k network. Advertised in {Packet::Hello}.
    # @return [String,nil]
    attr_reader :name

    # The version of the original eDonkey protocol running in the client's software. Nowadays always 60 ({EDONKEYVERSION}).
    # Advertised in {Packet::Hello}.
    # @return [Integer,nil]
    attr_reader :version

    # Pass `socket` to create a client that connected to us. Otherwise, pass `id` and `port`. If known, the `id` should
    # be the `ip`, otherwise it's the client's ID in the server they're connected to (see {#id}).
    # @param id [Integer] The ID of the client (see {#id})
    # @param port [Integer] The port the client is listening to.
    # @param socket [Socket] The socket, if we're already connected to the client.
    # @param core [Core] The core object to use when managing this client
    def initialize(id: nil, port: nil, socket: nil, core: nil)
      @core = core
      @id   = id
      @ready_tcp = false
      @ready_udp = false

      # Connection properties
      @socket      = socket
      @ip          = @socket ? @socket.remote_address.ip_address : high_id? ? ED2K.unpack_ip(@id) : nil
      @tcp_port    = port # (don't infer from socket, it's an incoming connection and thus the port is ephemeral)
      @server_ip   = nil
      @server_port = nil
      @server      = nil

      # Other properties
      @hash     = nil
      @name     = nil
      @version  = nil

      # UDP resources (incoming queue, UDP address), independent of any TCP connection
      #udp_setup()
    end

    def high_id?
      !!@id && @id > 0xFFFFFF
    end

    # Format the client's name in human-readable form
    # @return [String] `ID@IP:Port 'Name'`
    def format_name
      "%s (%d@%s:%d)" % [@name || '(?)', @id || 0, @ip || '(?)', @tcp_port || 0]
    end

    # Send a Hello or HelloAnswer packet to this server / client. This packet should be the first one after establishing
    # a successful TCP connection. It should also be sent in response to a received Hello packet, with `answer: true`.
    # It is used to exchange information and capabilities. Note it's also received from servers during the High ID flow.
    # @param answer [Boolean] Whether this packet is a Hello or a HelloAnswer packet.
    def send_hello(answer, hash, id, port: @core.tcp_port, server_ip: 0, server_port: 0, name: nil, version_edonkey: EDONKEYVERSION)
      data = answer ? ''.b : "\x10".b
      tag_count = 2 + (name ? 1 : 0)
      data = [hash, id, port, tag_count].pack('a16L<S<L<')
      data << Tag::write(CT_NAME, name) if name
      data << Tag::write(CT_VERSION, version_edonkey)
      data << Tag::write(CT_PORT, port)
      data << [server_ip, server_port].pack('L<S<')
      queue_tcp_packet(OP_EDONKEYPROT, answer ? OP_HELLOANSWER : OP_HELLO, data)
      @core.log_debug("Sent hello#{answer ? ' answer' : ''} request to #{format_name()}")
    end

    private

    # Parse a packet sent by the client with the standard edonkey protocol. Returns the data in a standard form so
    # that the custom handlers can consume it.
    def parse_edonkey_tcp_packet(opcode, packet)
      case opcode
      when OP_HELLO, OP_HELLOANSWER
        parse_hello(packet, opcode == OP_HELLOANSWER)
      else
        Packet::Raw.new(OP_EDONKEYPROT, opcode, packet)
      end
    end

    # Parse a Hello packet. For now, we only parse the bare minimum required for communicating with servers.
    # TODO: Parse the Server and add it to the list
    def parse_hello(packet, answer)
      if packet.size < (answer ? 0 : 1) + 16 + 4 + 2 + 4 # Hello packet starts with hash size, HelloAnswer doesn't
        @core.log_debug("Corrupt hello packet (too short)")
        return
      end
      packet = StringIO.new(packet)
      packet.read(1) unless answer
      @hash, @id, @tcp_port = packet.read(16 + 4 + 2).unpack('a16L<S<')
      tags = Tag.read(packet, core: @core)
      if !tags
        @core.log_debug("Failed to parse tags in client hello packet from #{format_name()}")
      else
        @name, @version, port = tags[CT_NAME], tags[CT_VERSION], tags[CT_PORT]
        tags.reject!{ |k, v| [CT_NAME, CT_VERSION, CT_PORT].include?(k) }
        if port && port != @tcp_port
          @core.log_debug("Received different ports in hello packet: #{@tcp_port} vs #{port}")
          @tcp_port = port
        end
      end
      @server_ip, @server_port = packet.read(6).unpack('L<S<') if packet.size - packet.pos >= 6
      @core.log_debug(
        "Received hello packet from #{format_name()}: hash=#{@hash.unpack1('H*')}, "\
        "id=#{@id}, port=#{@tcp_port}, name=#{@name}, version=#{@version}, more tags=#{tags&.size}"
      )
      Packet::Hello.new(answer, @hash, @id, @tcp_port, @server_ip, @server_port, @name, @version)
    end

  end # Client

end # ED2K
