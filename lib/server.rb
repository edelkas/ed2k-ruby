module ED2K

  # An ED2K [server](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=1267&rm=show_topic) is a node in the
  # ed2k network that serves the purpose of interconnecting users. It doesn't host any files, but it indexes all clients
  # connected to it, as well as all files available and which clients can provide at least part of them, i.e., its sources.
  #
  # Servers are hosts running the [eserver](http://web.archive.org/web/20071012044411/http://lugdunum2k.free.fr/kiten.html)
  # (_edonkey server_) software, which is a free but closed source implementation that handles all the necessary database
  # and networking resources. The latest version, dating from 2006, is [Lugdunum 17.15](https://www.emule-security.org/download.php?view.15),
  # which all main servers implement.
  #
  # There are two ways of communicating with a server:
  #
  # - For stable long-standing connections a TCP stream is used, this is known as _logging in_ the server. In this scenario,
  #   the client will share its files and they will be indexed, and the client will remain as an available source for them
  #   while connected. After logging in, the server will attempt to determine if connections can also be established with
  #   the client, leading to two different scenarios:
  #
  #     * If they can, the [ID assigned](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=103)
  #       to the client will be its IPv4 address. This scenario is known as **High ID** and indicates that other clients can
  #       freely talk to it without having to first route the requests through the server, reducing bandwidth and enabling
  #       communication between users in different servers.
  #
  #     * Otherwise, a random 3-byte ID (below ~16.7M) will be assigned instead, known as a **Low ID**. Since this increases
  #       server bandwidth and reduces communication capabilities between clients, servers normally cap the amount of low
  #       ID users they allow (originally 20% by default, but nowadays often raised to about 80%).
  #
  # - For sporadic short-term requests that don't require a connection UDP messages are used instead. This is the case of
  #   *Global Searches*, for instance, which performs a search query in all servers without necessarily being logged in them.
  #   The eMule extended protocol added several client to client UDP queries added as well, see {Client} for more info.
  #
  # Nothing prevents a client from logging in to multiple servers simultaneously, despite the most well-known software,
  # eMule, imposing that restriction. Indeed, other tools like MLDonkey enable it, and likewise, a {Core} can connect to
  # any amount of servers.
  #
  # Servers have a [limit](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=150) on how many
  # files they will index for each client. Originally this limit was very modest, around 500, but nowadays they are usually
  # at least 1M. The **Soft File Limit** is the amount of files that will be indexed without consequences, while the
  # **Hard File Limit** is the amount that will get a client disconnected if surpassed. It doesn't make sense to share
  # more files than the soft limit, so a {Server} object will always remain within that boundary.
  class Server
    include Connection

    # The processed payload of an IDCHANGE packet (see {#parse_id_change}). Note that the IP and ports are optional
    # and might be `nil`. The capability flags (`support_...`) should always be there for "modern" (16.44+) servers.
    IdChangeStruct = Struct.new(:server, :id, :ip, :port, :obfuscated_port, :support_compression, :support_newtags,
      :support_unicode, :support_related, :support_filetypes, :support_largefiles, :support_obfuscation)

    # @param ip [String] The public IPv4 address of the server
    # @param port [Integer] The port the server is listening to for incoming connections
    # @param core [Core] The core object to use when managing this server
    def initialize(ip, port, core: nil)
      @core = core

      # Basic properties we need to establish a connection or send packets
      @ip      = ip
      @port    = port
      @address = Addrinfo.new(Socket.pack_sockaddr_in(@port, @ip))

      # These properties aren't known until we query the server's status and description
      @name        = ''
      @description = ''
      @ping        = -1
      @files       = -1
      @max_users   = -1
      @users       = -1
      @low_id      = -1
      @soft_limit  = -1
      @hard_limit  = -1
      @version     = -1
      @obfuscation = false
    end

    # Format the server's name in human-readable form
    # @return [String] Nick (IP:Port)
    def format_name
      ip = "%s:%d" % [@address.ip_address, @address.ip_port]
      @name ? "#{@name} (#{ip})" : ip
    end

    # Parse a packet sent by the server with the standard edonkey protocol. Returns the data in a standard form so
    # that the custom handlers can consume it.
    # @param opcode [Integer] The packet's identifying opcode.
    # @param packet [String] The packet's payload, without the header.
    # @return Packet-specific processed payload.
    def parse_edonkey_packet(opcode, packet)
      case opcode
      when OP_SERVERMESSAGE
        parse_server_message(packet)
      when OP_IDCHANGE
        parse_id_change(packet)
      else
        @core.log("Received unsupported server edonkey packet %#.2x from #{format_name()}" % opcode)
      end
    end

    # Informative notices sent by the server. A packet can contain multiple messages separated by new lines.
    # Some standard ones have special meanings:
    #
    # - `ERROR: ...` -> An error message, usually printed red by eMule.
    # - `WARNING: ...` -> A warning message, usually printed purple by eMule.
    # - `server version xx.xx` -> The version of eserver running, nowadays usually 17.15.
    # - `[emDynIP: StaticHostName.host:Port]` -> Server instructs us to use DNS because their IP is dynamic and thus subject to change
    #   ([read more](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=132&rm=show_topic)).
    # @param packet [String] The raw packet payload.
    # @return [Array<String>] The messages in this packet.
    def parse_server_message(packet)
      length, messages = packet.unpack('S<A*')
      messages.split("\r\n").map(&:strip).each{ |msg|
        @core.log("Received server message from #{format_name()}: #{msg}")
      }
    end

    # Received whenever our session ID changes in the server. This usually only happens when we log into the server, and
    # it contains our assigned ID, but technically it can happen at any time, so it should be carefully monitored. Since
    # Lugdunum 16.44 it also contains flags with server capabilities, as well as additional information about our client.
    # @param packet [String] The raw payload.
    # @return [IdChangeStruct] The processed payload.
    def parse_id_change(packet)
      id, flags, port, ip, obfuscated_port = packet.unpack('L<5')
      flags ||= 0
      @core.log("Received new ID from #{format_name()}: #{id}")
      @core.log("Our IP is #{[ip].pack('L>').unpack('C4').join('.')}") if ip
      IdChangeStruct.new(
        self, id, ip, port, obfuscated_port,
        flags & SRV_TCPFLG_COMPRESSION    > 0,
        flags & SRV_TCPFLG_NEWTAGS        > 0,
        flags & SRV_TCPFLG_UNICODE        > 0,
        flags & SRV_TCPFLG_RELATEDSEARCH  > 0,
        flags & SRV_TCPFLG_TYPETAGINTEGER > 0,
        flags & SRV_TCPFLG_LARGEFILES     > 0,
        flags & SRV_TCPFLG_TCPOBFUSCATION > 0
      )
    end

    # Send login request to the server. We communicate basic information about ourselves, as well as client capabilities
    # and versioning. You don't really need to change any of the options in most scenarios.
    #
    # This should be the first packet we send to a server after establishing a TCP connection. After this, the server will
    # try to establish a *different* TCP connection to us on the specified port to determine if we're reachable and thus
    # should be assigned a **high ID**, otherwise we'll be assigned a **low ID**. Either way, if login is succesful we'll
    # receive an `IDCHANGE` packet with our assigned ID. At this point we can consider the login process finished and start
    # sending other packets. The server can send us further notices via the `SERVERMESSAGE` packet, including if our login
    # was rejected. There's also a specific `REJECT` packet sent when any query is rejected.
    # @note Some options, like compression or protocol obfuscation, can't be enabled for now because they aren't supported yet.
    # @param hash [String] Our 16-byte client hash that identifies us in the network
    # @param name [String] Our nickname as it shows to other clients
    # @param port [Integer] The TCP port we are listening to for incoming connections from the server and other clients
    # @param id [Integer] Our client ID. This is assigned by the server itself, so its usually 0 the first time we connect.
    # @param support_compression [Boolean] If we support compressed packets via the packed protocol ({OP_PACKEDPROT}). **Currently not available**.
    # @param support_newtags [Boolean] If we support new-style Lugdunum tags (see {#write_tag}).
    # @param support_largefiles [Boolean] If we support 64 bit file sizes (i.e. >4GB).
    # @param support_unicode [Boolean] If we support Unicode strings for filenames, nicknames, etc.
    # @param support_obfuscation [Boolean] If we support protocol obfuscation. **Currently not available**.
    # @param request_obfuscation [Boolean] If we also request other clients to use it when connecting to us. **Currently not available**.
    # @param require_obfuscation [Boolean] If we reject non-obfuscated connections. **Currently not available**.
    # @param version_major [Integer] Major eMule version (7 bits, 0-99). Default: `0` (see {VERSION_MJR}).
    # @param version_minor [Integer] Minor eMule version (7 bits, 0-99). Default: `50` (see {VERSION_MIN}).
    # @param version_update [Integer] Version update (3 bits, 0-5). Default: `1` (see {VERSION_UPDATE}).
    # @param version_edonkey [Integer] Underlying eDonkey2000 client version. Default: `60` (see {EDONKEYVERSION}).
    def login(
      hash, name, port, id: 0,
      support_compression: false, support_newtags: true, support_largefiles: true, support_unicode: true,
      support_obfuscation: false, request_obfuscation: false, require_obfuscation: false,
      version_major: VERSION_MJR, version_minor: VERSION_MIN, version_update: VERSION_UPDATE, version_edonkey: EDONKEYVERSION
    )
      # We don't support compressed packets nor protocol obfuscation for now
      support_compression = false
      support_obfuscation = false
      request_obfuscation = false
      require_obfuscation = false

      # Basic user info
      tag_count = 4
      data = [hash, id, port, tag_count].pack('a16L<S<L<')
      data << write_tag(CT_NAME, name)
      data << write_tag(CT_VERSION, version_edonkey)

      # Client capabilities
      flags = 0
      flags |= SRVCAP_ZLIB         if support_compression
      flags |= SRVCAP_NEWTAGS      if support_newtags
      flags |= SRVCAP_LARGEFILES   if support_largefiles
      flags |= SRVCAP_UNICODE      if support_unicode
      flags |= SRVCAP_SUPPORTCRYPT if support_obfuscation
      flags |= SRVCAP_REQUESTCRYPT if request_obfuscation
      flags |= SRVCAP_REQUIRECRYPT if require_obfuscation
      data << write_tag(CT_SERVER_FLAGS, flags)

      # Versioning info
      version = version_major << 17 | version_minor << 10 | version_update << 7
      data << write_tag(CT_EMULE_VERSION, version)

      queue_packet(OP_EDONKEYPROT, OP_LOGINREQUEST, data)
      @core.log("Sent login request to #{format_name()}")
    end

  end # Server
end # ED2K
