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
  #
  # @todo We need to ensure we're connected to the servers before sending the TCP packets!
  #       Even for the UDP packets, we'll first need to ensure the server is known by the core (in @servers).
  #       A good way of doing so is by doing all this from the core, and making the methods here private.
  class Server
    include Connection

    TIMEOUT_LOGIN = 30 # Maximum time in seconds to wait for a server's answer to our login request

    # The DNS to use to communicate with the server instead of the fixed IP address. Used by servers under dynamic IP
    # regimes. Advertised in a {Packet::ServerMessage}, rarely seen.
    # @return [String,nil]
    attr_reader :dns

    # The server's public name. Advertised in {Packet::ServerIdentification}.
    # @return [String,nil]
    attr_reader :name

    # The server's short description. Advertised in {Packet::ServerIdentification}.
    # @return [String,nil]
    attr_reader :description

    # The server's identification MD4 hash. This acts as a sort of GUID, and some old servers used it to identify
    # themselves, but nowadays it's mostly useless. Advertised in {Packet::ServerIdentification}, as well as in
    # {Packet::Hello} during the High ID flow.
    # @return [String,nil]
    attr_reader :hash

    # The version of the eserver software running the server, usually as `MAJOR.MINOR`. The latest official eserver
    # version is `17.15`, dating from 2006. Custom servers might specify a different one. Advertised as a special
    # {Packet::ServerMessage} after logging in.
    # @return [String,nil]
    attr_reader :version

    # The count of users currently connected to the server. Advertised in {Packet::ServerStatus} periodically.
    # @return [Integer,nil]
    attr_reader :users

    # The count of Low ID users currently connected to the server. Currently unsupported, as this is only advertised in
    # a UDP packet.
    # @return [nil]
    attr_reader :low_id

    # Maximum amount of concurrent users supported by the server. Currently unsupported, as this is only advertised in a
    # UDP packet.
    # @return [nil]
    attr_reader :max_users

    # The total file count indexed by the server. Advertised in {Packet::ServerStatus} periodically.
    # @return [Integer,nil]
    attr_reader :files

    # The soft file limit determines the maximum number of files a client may share in the server before discarding
    # the rest. Currently unsupported, as this is only advertised in a UDP packet.
    # @return [nil]
    attr_reader :soft_limit

    # The hard file limit determines the maximum number of files a client may share in the server before being kicked
    # out. Currently unsupported, as this is only advertised in a UDP packet.
    # @return [nil]
    attr_reader :hard_limit

    # The TCP flags sent in {Packet::IdChange} after logging in to the server. It's a bitmask containing capabilities
    # supported by the server, many of which we don't support ourselves yet. You may prefer using the individual
    # helpers `supports_*` (e.g. {#supports_unicode}).
    # @return [Integer,nil]
    attr_reader :tcp_flags

    # @param ip [String] The public IPv4 address of the server
    # @param port [Integer] The port the server is listening to for incoming connections
    # @param core [Core] The core object to use when managing this server
    def initialize(ip, port, core: nil)
      @core = core

      # Basic properties we need to establish a connection or send packets
      @ip          = ip
      @tcp_port    = port
      @dns         = nil

      # Server status, identification and capabilities. These properties aren't known until receiving certain packets.
      @name        = nil
      @description = nil
      @hash        = nil
      @version     = nil
      @files       = 0
      @max_users   = nil
      @users       = 0
      @low_id      = nil
      @soft_limit  = nil
      @hard_limit  = nil
      @tcp_flags   = 0

      # Server state w.r.t. our client
      @pending_login = false # Are we awaiting an answer for our login request
      @login_time    = nil   # Since when?

      # UDP resources (incoming queue, UDP address), independent of any TCP connection
      #udp_setup()
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
    # @param id [Integer] Our client ID. This is assigned by the server itself, so its usually 0 the first time we connect.
    # @param port [Integer] The TCP port we are listening to for incoming connections from the server and other clients.
    # @param support_compression [Boolean] If we support compressed packets via the packed protocol ({OP_PACKEDPROT}). **Currently not available**.
    # @param support_newtags [Boolean] If we support new-style Lugdunum tags (see {Tag.write}).
    # @param support_largefiles [Boolean] If we support 64 bit file sizes (i.e. >4GB).
    # @param support_unicode [Boolean] If we support Unicode strings for filenames, nicknames, etc.
    # @param support_obfuscation [Boolean] If we support protocol obfuscation. **Currently not available**.
    # @param request_obfuscation [Boolean] If we also request other clients to use it when connecting to us. **Currently not available**.
    # @param require_obfuscation [Boolean] If we reject non-obfuscated connections. **Currently not available**.
    # @param version_major [Integer] Major eMule version (7 bits, 0-99). Default: `0` (see {VERSION_MJR}).
    # @param version_minor [Integer] Minor eMule version (7 bits, 0-99). Default: `50` (see {VERSION_MIN}).
    # @param version_update [Integer] Version update (3 bits, 0-5). Default: `1` (see {VERSION_UPDATE}).
    # @param version_edonkey [Integer] Underlying eDonkey2000 client version. Default: `60` (see {EDONKEYVERSION}).
    def send_login(
      hash, name, id: 0, port: @core.tcp_port,
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
      data << Tag::write(CT_NAME, name)
      data << Tag::write(CT_VERSION, version_edonkey)

      # Client capabilities
      flags = 0
      flags |= SRVCAP_ZLIB         if support_compression
      flags |= SRVCAP_NEWTAGS      if support_newtags
      flags |= SRVCAP_LARGEFILES   if support_largefiles
      flags |= SRVCAP_UNICODE      if support_unicode
      flags |= SRVCAP_SUPPORTCRYPT if support_obfuscation
      flags |= SRVCAP_REQUESTCRYPT if request_obfuscation
      flags |= SRVCAP_REQUIRECRYPT if require_obfuscation
      data << Tag::write(CT_SERVER_FLAGS, flags)

      # Versioning info
      version = version_major << 17 | version_minor << 10 | version_update << 7
      data << Tag::write(CT_EMULE_VERSION, version)

      queue_tcp_packet(OP_EDONKEYPROT, OP_LOGINREQUEST, data)
      self.pending_login = true
      @core.log_info("Sent login request to #{format_name()}")
    end

    # Request the list of known servers to this server.
    def send_server_list_request
      queue_tcp_packet(OP_EDONKEYPROT, OP_GETSERVERLIST)
      @core.log_debug("Sent server list request to #{format_name()}")
    end

    # Whether we've sent a login request to this server and haven't received an answer yet. Servers reply to a login by
    # opening a TCP connection back to us, to check whether we're reachable and thus deserve a High ID, and that's
    # essentially the only reason they ever connect to us. This makes the flag a useful hint to tell apart several
    # servers sharing a single IP address when one of them connects to us (see {Core#get_server}).
    #
    # An answer may simply never arrive, so the flag expires on its own after {TIMEOUT_LOGIN} seconds rather than
    # lingering forever and skewing every later disambiguation towards this server. It's checked here, when read, so
    # that no timer or periodic sweep is needed.
    # @return [Boolean]
    def pending_login
      return false if !@pending_login
      return true if Time.now - @login_time <= TIMEOUT_LOGIN
      @pending_login = false
      @core.log_debug("Login request to #{format_name()} went unanswered for #{TIMEOUT_LOGIN}s, no longer expecting a reply")
      false
    end

    # Format the server's name in human-readable form.
    # @return [String] Nick (IP:Port)
    def format_name
      @name ? "#{@name} (#{@ip}:#{@tcp_port})" : "#{@ip}:#{@tcp_port}"
    end

    # Whether this server supports sending and receiving compressed packets. It will be done automatically by this gem,
    # unless otherwise specified, provided both server and client support it. This was introduced in eserver 16.40 /
    # eMule0.30b via the packed protocol ({OP_PACKEDPROT}) to save bandwidth, and is typically used for search results
    # or when we send our shared files list, only when both server and client support it. **Currently unsupported**.
    # @return [Boolean]
    def supports_compression
      @tcp_flags && @tcp_flags & SRV_TCPFLG_COMPRESSION > 0
    end

    # Whether this server supports new-style tags. This is an internal feature that most users shouldn't concern themselves
    # with, it will be used automatically by the gem whenever possible. It allows to compress tags in packets, and
    # was introduced in eserver 16.46 / eMule0.42f. See {Tag} for the technical details.
    # @return [Boolean]
    def supports_newtags
      @tcp_flags && @tcp_flags & SRV_TCPFLG_NEWTAGS > 0
    end

    # Whether this server supports Unicode strings (for file names, user names, etc). Introduced in eserver 17.1 /
    # eMule0.44a.
    # @return [Boolean]
    def supports_unicode
      @tcp_flags && @tcp_flags & SRV_TCPFLG_UNICODE > 0
    end

    # Whether this server supports searching for related files (the "Related" search in eMule). Introduced in
    # eserver 17.5 / eMule0.46b.
    # @return [Boolean]
    def supports_related_search
      @tcp_flags && @tcp_flags & SRV_TCPFLG_RELATEDSEARCH > 0
    end

    # Whether this server supports searching for file types using integer tags (e.g. audio is 1). Introduced in eserver
    # 17.6.
    # @return [Boolean]
    def supports_filetype_search
      @tcp_flags && @tcp_flags & SRV_TCPFLG_TYPETAGINTEGER > 0
    end

    # Whether this server supports 64-bit file sizes, and thus files over 4GB. Sizes are nonetheless limited to 256GB,
    # at least on eMule's side. Introduced in eserver 17.8 / emule0.47a.
    # @return [Boolean]
    def supports_large_files
      @tcp_flags && @tcp_flags & SRV_TCPFLG_LARGEFILES > 0
    end

    # Whether this server supports obfuscated TCP packets. Protocol obfuscation was added in eserver 17.13 / eMule0.47b,
    # see {Obfuscation} for more information. **Currently unsupported**.
    # @return [Boolean]
    def supports_tcp_obfuscation
      @tcp_flags && @tcp_flags & SRV_TCPFLG_TCPOBFUSCATION > 0
    end

    private

    # Mark whether we're awaiting an answer to our login request, starting the countdown to {TIMEOUT_LOGIN} when we are.
    def pending_login=(pending)
      @pending_login = pending
      @login_time = pending ? Time.now : nil
    end

    # Parse a packet sent by the server with the standard edonkey protocol. Returns a Packet object, ideally a subclass
    # unless there's no good fit due to the packet being unsupported. Returns nil if the packet is corrupt.
    def parse_edonkey_tcp_packet(opcode, packet)
      case opcode
      when OP_HELLO, OP_HELLOANSWER
        parse_hello(opcode, packet)
      when OP_REJECT
        parse_reject()
      when OP_SERVERLIST
        parse_server_list(packet)
      when OP_SERVERSTATUS
        parse_server_status(packet)
      when OP_SERVERMESSAGE
        parse_server_message(packet)
      when OP_IDCHANGE
        parse_id_change(packet)
      when OP_SERVERIDENT
        parse_server_identification(packet)
      else
        Packet::Raw.new(OP_EDONKEYPROT, opcode, packet)
      end
    end

    # Received when our last command was rejected by the server. There's no payload.
    def parse_reject()
      self.pending_login = false # The rejection may well be for our login request, don't wait for an answer any longer
      @core.log_debug("Last command was rejected by server #{format_name()}")
      Packet::Reject.new
    end

    # Contains the server's list of other known servers. Requested by the client via {#send_server_list_request}.
    def parse_server_list(packet)
      count = packet.unpack1('C')
      if packet.size < 1 + 6 * count
        @core.log_debug("Received corrupt server list packet from #{format_name()}")
        return
      end
      servers = packet.unpack('L<S<' * count, offset: 1).each_slice(2).to_a
      @core.log_info("Received #{count} servers from #{format_name()}")
      servers.each{ |ip, port| @core.log_debug("%15s:%d" % [ED2K::unpack_ip(ip), port]) }
      Packet::ServerList.new(servers)
    end

    # Contains the server's current user and file count. Received after logging in, and also periodically as pings.
    def parse_server_status(packet)
      if packet.size < 8
        @core.log_debug("Received corrupt server status from #{format_name()}")
        return
      end
      @users, @files = packet.unpack('L<2')
      @core.log_debug("Received server status from #{format_name()}: #{@users} users, #{@files} files")
      Packet::ServerStatus.new(@users, @files)
    end

    # Received when the server sends us messages. A packet can contain multiple messages separated by new lines.
    def parse_server_message(packet)
      if packet.size < 2
        @core.log_debug("Received corrupt server message from #{format_name()}")
        return
      end
      length = packet.unpack1('S<')
      messages = packet.unpack1("a#{length}", offset: 2)
      messages = messages.each_line{ |msg|
        if msg.start_with?(/error/i)
          @core.log_error("Received error from #{format_name()}: #{msg}")
        elsif msg.start_with?(/warning/i)
          @core.log_warning("Received warning from #{format_name()}: #{msg}")
        else
          @core.log_info("Received server message from #{format_name()}: #{msg}")
        end
        if msg.start_with?(/server version\s*(\d+).(\d+)/i)
          @version = $1 + '.' + $2
          @core.log_debug("Received new server version: #{@version}")
        end
        if msg =~ /\[emDynIP: (.+)\]/i
          @dns = $1
          @core.log_debug("Received DNS from #{format_name()}: #{@dns}")
        end
      }
      Packet::ServerMessage.new(messages)
    end

    # Received whenever our session ID changes in the server.
    def parse_id_change(packet)
      if packet.size < 4
        @core.log_debug("Received corrupt ID change packet from #{format_name()}")
        return
      end
      id, flags, _, ip, obfuscated_tcp_port = packet.unpack('L<5')
      @tcp_flags = flags if flags
      flags ||= 0
      self.pending_login = false # The ID assignment is the answer to our login request
      @core.log_info("Received new ID from #{format_name()}: #{id}")
      @core.log_debug("Received ID change packet: id=#{id}, flags=#{flags}, ip=#{ED2K::unpack_ip(ip || 0)}, obfTCPport=#{obfuscated_tcp_port}")
      Packet::IdChange.new(id, flags, ip, obfuscated_tcp_port)
    end

    # Contains server information, such as name and description. Received after requesting the server list.
    def parse_server_identification(packet)
      if packet.size < 16 + 4 + 2 + 4
        @core.log_debug("Received corrupt server identification packet from #{format_name()}")
        return
      end
      @hash, ip, port = packet.unpack('a16L<S<')
      tags = Tag.read(packet, 22, core: @core)
      if !tags
        @core.log_debug("Failed to parse tags in server identification packet from #{format_name()}")
        name, description = nil, nil
      else
        name, description = tags[ST_SERVERNAME], tags[ST_DESCRIPTION]
        tags.reject!{ |k, v| k == ST_SERVERNAME || k == ST_DESCRIPTION }
      end
      @name = name if name
      @description = description if description
      @core.log_debug(
        "Received server identification packet from #{format_name()}: hash=#{@hash.unpack1('H*')}, "\
        "ip=#{ED2K::unpack_ip(ip)}, port=#{port}, name=#{name}, description=#{description}, more tags=#{tags.size}"
      )
      Packet::ServerIdentification.new(@hash, ip, port, name, description, tags || {})
    end

  end # Server
end # ED2K
