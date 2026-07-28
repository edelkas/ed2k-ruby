module ED2K

  # Wrapper for ed2k packets. All communications in the **ed2k** and **Kad** networks take place by exchanging these packets.
  # This gem uses {Packet} objects mostly for incoming packets, so the user can recognize and parse them. Since outgoing
  # packets are queued by their respective high-level methods (e.g. {Server#send_login}), the user doesn't really need to
  # manually instantiate those.
  #
  # ## Structure
  #
  # The following technical information is not required for using the gem, it's only presented for documentation purposes.
  #
  # Packet headers:
  # - **TCP** packets have a 6-byte header: protocol (char), size (uint32) and opcode (char).
  # - **UDP** packets have a 2-byte header: protocol (char) and opcode (char).
  #
  # The **protocol** specifies the overall structure of the packet, and what family of operations to utilize.
  # The network defines 5 protocols:
  # - eDonkey protocol (`0xE3`, see {OP_EDONKEYPROT}) is the classic (and originally, only) protocol.
  # - eMule protocol (`0xC5`, see {OP_EMULEPROT}) comprises a series of extensions added by eMule and supported by compatible clients.
  # - Packed protocol (`0xD4`, see {OP_PACKEDPROT}) compresses packets via zlib from the previous two protocols.
  # - Kademlia protocol (`0xE4`, see {OP_KADEMLIAHEADER}) is used for the serverless Kad network.
  # - Packed Kademlia protocol (`0xE5`, see {OP_KADEMLIAPACKEDPROT}) compresses regular Kad packets.
  #
  # The **opcode** identifies the exact packet type, and thus, its expected payload. However, it is worth noting that opcodes
  # _can_ overlap in the following 3 scenarios:
  # - If the _channel_ is different: TCP vs TDP.
  # - If the _protocol_ is different: the same opcode could be used with different meanings in each of the 5 protocols above.
  # - If the _direction_ is different: Server->Client vs Client->Server vs Client->Client.
  #
  # So a parser must be selected carefully taking into account all of the above factors.
  #
  # The **size** field is the length of the packet in bytes _minus 5_ (i.e. excluding the protocol and size fields, but notably,
  # including the opcode field). This field is only required for TCP packets, as UDP packets' lengths can be inferred from
  # the UDP headers and don't require any buffering.
  class Packet

    # The packet's ed2k protocol, can be one of five: {OP_EDONKEYPROT}, {OP_EMULEPROT}, {OP_PACKEDPROT},
    # {OP_KADEMLIAHEADER} or {OP_KADEMLIAPACKEDPROT}.
    # @return [Integer]
    attr_reader :protocol

    # The packet's protocol-dependent opcode identifies the packet type.
    # @return [Integer]
    attr_reader :opcode

    # @param protocol [Integer] See {#protocol}.
    # @param opcode [Integer] See {#opcode}.
    def initialize(protocol, opcode)
      @protocol = protocol
      @opcode = opcode
    end

    # Auxiliary class to store unsupported or corrupt packets by saving the raw payload instead of parsing it.
    # This is used predominantly for two scenarios:
    # - The packet is valid, but we still don't support it, so we have no subclass that fits.
    # - The packet's header is valid, but the payload is corrupt or we failed to parse it.
    #
    # Whenever a packet is supported and parses properly, the corresponding {Packet} subclass should be used instead.
    # If even the header is invalid the packet is dropped altogether (see {Connection#process_tcp_packet}).
    class Raw < Packet

      # The packet's raw payload, could be empty.
      # @return [String]
      attr_reader :payload

      # @param protocol [Integer] See {#protocol}.
      # @param opcode [Integer] See {#opcode}.
      # @param payload [String] See {#payload}.
      def initialize(protocol, opcode, payload)
        super(protocol, opcode)
        @payload = payload
      end
    end

    # TCP packet sent by servers with their list of other known servers.
    # - Request this packet with {Server#send_server_list_request}.
    # - Set a handler for these packets with {Core#handle_server_list}.
    class ServerList < Packet

      # List of server TCP addresses
      # @return [Array<Addrinfo>]
      attr_reader :servers

      # @param servers [Array<[String,Integer]>] List of servers as an array of IP address and port pairs.
      def initialize(servers)
        super(OP_EDONKEYPROT, OP_SERVERLIST)
        @servers = servers.map{ |ip, port| Addrinfo.new(Socket.pack_sockaddr_in(port, ip)) }
      end
    end

    # TCP packet sent by servers with their current user and file count.
    # - Received after logging in (via {Server#send_login}).
    # - Set a handler for these packets with {Core#handle_server_status}.
    class ServerStatus < Packet

      # Amount of users currently connected to the server
      # @return [Integer]
      attr_reader :users

      # Amount of files currently indexed by the server
      # @return [Integer]
      attr_reader :files

      # @param users [Integer] User count, see {#users}.
      # @param files [Integer] File count, see {#files}.
      def initialize(users, files)
        super(OP_EDONKEYPROT, OP_SERVERSTATUS)
        @users = users
        @files = files
      end
    end

    # TCP packet sent by servers to inform one of our last operations was rejected. It has no payload.
    # - Received when the server rejects a previous operation.
    # - Set a handler for these packets with {Core#handle_reject}.
    class Reject < Packet
      def initialize
        super(OP_EDONKEYPROT, OP_REJECT)
      end
    end

    # TCP packet sent by servers with informative notices. Multiple messages can be included on a single packet, separated
    # in different lines.
    # - Received whenever the server we're connected to wants to send us a message (on login, on error, etc).
    # - Set a handler for these packets with {Core#handle_server_message}.
    #
    # Importantly, certain messages (lines) carry special meaning that should be handled with care:
    # - If the message starts with `ERROR` or `WARNING` the server is explicitly informing us of a problem. eMule logs
    #   these in red or purple, respectively.
    # - If the message starts with `server version` it's usually followed by "x.y", where "x" is the major version, and
    #   "y" is the minor version of the eserver software running in this server (e.g. 17.15).
    # - If the message contains a string of the form `[emDynIP: DNS_HERE]`, then the server is under a
    #   dynamic IP regime, and is informing us to use the specified DNS instead. The host name length is below 51 chars.
    #   See [eMule Project](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=132&rm=show_topic) for more info.
    #
    # These are parsed automatically by this class, but the raw message is left untouched.
    class ServerMessage < Packet

      # The message sent. Can span multiple lines / multiple messages.
      # @return [String]
      attr_reader :message

      # The eserver version indicated by this message, in the form `MAJOR.MINOR`, if present.
      # @return [String,nil]
      attr_reader :version

      # The server's host name that should be used instead of the IP address.
      # @return [String]
      attr_reader :dns

      # Whether this message contains an error.
      # @return [Boolean]
      attr_reader :has_error

      # Whether this message contains a warning.
      # @return [Boolean]
      attr_reader :has_warning

      # @param message [String] The raw message string sent by the server.
      def initialize(message)
        super(OP_EDONKEYPROT, OP_SERVERMESSAGE)
        @message = message
        @error = false
        @warning = false
        @dns = nil
        @message.each_line do |msg|
          if msg.start_with?(/error/i)
            @has_error = true
          elsif msg.start_with?(/warning/i)
            @has_warning = true
          elsif msg.start_with?(/server version\s*(\d+).(\d+)/i)
            @version = $1 + '.' + $2
          end
          @dns = $1 if msg =~ /\[emDynIP: (.+)\]/i
        end
      end
    end

    # TCP packet sent by a server to inform us of our new ID in the server, and some additional server properties and
    # capabilities. These properties will be stored and handled automatically by the gem whenever relevant.
    # - Received whenever our ID is set or changes, notably after login (via {Server#send_login}).
    # - Set a handler for these packets with {Core#handle_id_change}.
    #
    # Note there are two types of IDs:
    # - **High ID**: If the ID is a full 4-byte integer it will always be our external IP address, and it means we are
    #   able to receive incoming TCP connections from the network. This is the ideal regime for optimal ed2k network usage.
    # - **Low ID**: If the ID is only 3 bytes (i.e. below ~16.7M) then it's a random value assigned by the server. This
    #   means we are unreachable in the ed2k network. In this situation we'll be able to communicate with fewer client,
    #   find fewer sources, etc.
    #
    # A high ID user and a low ID user can only communicate if they're connected to the same server via the callback
    # mechanism. Two low ID users cannot communicate in any way. See {Server} for more info.
    class IdChange < Packet

      # The ID we've been assigned in the server. Will match our external IP if we have High ID.
      # @return [Integer]
      attr_reader :id

      # The server's TCP flags, a bitmask containing supported capabilities.
      # @see All All the "supports_*" methods.
      # @return [Integer]
      attr_reader :flags

      # Our external IP as reported by the server. Not always present. If it matches our ID then we have High ID.
      # @return [Integer]
      attr_reader :ip

      # The port we should use for obfuscated TCP connections with this server. Not always present.
      # @return [Integer]
      attr_reader :obf_tcp_port

      # @param id [Integer] Our ID in the server, see {#id}.
      # @param flags [Integer] The server's TCP flags, see {#flags}.
      # @param ip [Integer] Optional, our external IP as reported by the server, see {#ip}.
      # @param obf_tcp_port [Integer] Optional, the server's TCP port for obfuscated communications, see {#obf_tcp_port}.
      def initialize(id, flags, ip, obf_tcp_port)
        super(OP_EDONKEYPROT, OP_IDCHANGE)
        @id = id
        @flags = flags                 # eserver 16.44+
        @ip = ED2K.unpack_ip(ip) if ip # Not guaranteed
        @obf_tcp_port = obf_tcp_port   # Not guaranteed
      end

      # Whether we were assigned a High ID and are thus able to receive incoming TCP connections in the network.
      # @return [Boolean]
      def high?
        @ip && @id == ED2K.pack_ip(@ip)
      end

      # Whether this server supports sending and receiving compressed packets. It will be done automatically by this gem,
      # unless otherwise specified, provided both server and client support it. This was introduced in eserver 16.40 /
      # eMule0.30b via the packed protocol ({OP_PACKEDPROT}) to save bandwidth, and is typically used for search results
      # or when we send our shared files list, only when both server and client support it.
      # @return [Boolean]
      def supports_compression
        @flags && @flags & SRV_TCPFLG_COMPRESSION > 0
      end

      # Whether this server supports new-style tags. This is an internal feature that most users shouldn't concern themselves
      # with, it will be used automatically by the gem whenever possible. It allows to compress tags in packets, and
      # was introduced in eserver 16.46 / eMule0.42f. See {Tag} for the technical details.
      # @return [Boolean]
      def supports_newtags
        @flags && @flags & SRV_TCPFLG_NEWTAGS > 0
      end

      # Whether this server supports Unicode strings (for file names, user names, etc). Introduced in eserver 17.1 /
      # eMule0.44a.
      # @return [Boolean]
      def supports_unicode
        @flags && @flags & SRV_TCPFLG_UNICODE > 0
      end

      # Whether this server supports searching for related files (the "Related" search in eMule). Introduced in
      # eserver 17.5 / eMule0.46b.
      # @return [Boolean]
      def supports_related
        @flags && @flags & SRV_TCPFLG_RELATEDSEARCH > 0
      end

      # Whether this server supports searching for multiple file extensions. This enables the classic search by type
      # (e.g. "Video") instead of only individual extensions (e.g. "mkv"). Introduced in eserver 17.7.
      # @return [Boolean]
      def supports_filetypes
        @flags && @flags & SRV_TCPFLG_TYPETAGINTEGER > 0
      end

      # Whether this server supports 64-bit file sizes, and thus files over 4GB. Sizes are nonetheless limited to 256GB,
      # at least on eMule's side. Introduced in eserver 17.8 / emule0.47a.
      # @return [Boolean]
      def supports_largefiles
        @flags && @flags & SRV_TCPFLG_LARGEFILES > 0
      end

      # Whether this server supports obfuscated TCP packets. Protocol obfuscation was added in eserver 17.13 / eMule0.47b,
      # see {Obfuscation} for more information.
      # @return [Boolean]
      def supports_obfuscation
        @flags && @flags & SRV_TCPFLG_TCPOBFUSCATION > 0
      end
    end

    # TCP packet sent by a server containing some information details about it.
    # - Received after requesting the server list with {Server#send_server_list_request}.
    # - Set a handler for these packets with {Core#handle_server_identification}.
    class ServerIdentification < Packet

      # The server's MD4 hash. This seems to act as a sort of GUID, but it's completely unused. The only known usage is
      # to detect servers running the eFarm software (an obsolete eserver alternative dating from 2003), which would
      # have a hash of 0x2A2A2A2A.
      # @return [String]
      attr_reader :hash

      # The server's public IP address. Since this packet is sent in response to us, we already know this.
      # @return [Integer]
      attr_reader :ip

      # This server's TCP port for incoming connections. Since this packet is sent in response to us, we already know this.
      # @return [Integer]
      attr_reader :port

      # The server's public name.
      # @return [String]
      attr_reader :name

      # The server's public description.
      # @return [String]
      attr_reader :description

      # Additional tags sent by the server. This should always be empty, it's only here for sanity.
      # @return [Hash<TagName, TagValue>]
      attr_reader :tags

      def initialize(hash, ip, port, name, description, tags)
        super(OP_EDONKEYPROT, OP_SERVERIDENT)
        @hash = hash
        @ip = ED2K.unpack_ip(ip) if ip
        @port = port
        @name = name
        @description = description
        @tags = tags
      end
    end

  end # Packet

end # ED2K
