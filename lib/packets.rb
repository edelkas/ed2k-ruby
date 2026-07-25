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
  # So a parser must be selected carefully taking into account all of the above factors.
  #
  # The **size** field is the length of the packet in bytes _minus 5_ (i.e. excluding the protocol and size fields, but notably,
  # including the opcode field). This field is only required for TCP packets, as UDP packets' lengths can be inferred from
  # the UDP headers and don't require any buffering.
  class Packet

    # The packet's protocol, can be one of five: {OP_EDONKEYPROT}, {OP_EMULEPROT}, {OP_PACKEDPROT}, {OP_KADEMLIAHEADER}
    # or {OP_KADEMLIAPACKEDPROT}.
    # @return [Integer]
    attr_reader :protocol

    # Length of the packet's payload. It does _not_ include the header.
    # @return [Integer]
    attr_reader :size

    # The packet's opcode.
    # @return [Integer]
    attr_reader :opcode

    # @param protocol [Integer] The packet's protocol, can be one of five: {OP_EDONKEYPROT}, {OP_EMULEPROT}, {OP_PACKEDPROT},
    #                           {OP_KADEMLIAHEADER} or {OP_KADEMLIAPACKEDPROT}.
    # @param opcode [Integer] The packet's protocol-dependent opcode.
    # @param payload [String] The packet's content.
    def initialize(protocol, opcode, payload = '')
      @protocol = protocol
      @opcode = opcode
      @payload = payload
      @size = @payload.size
    end

    # Serialize the packet's payload
    def payload

    end

    # Send the packet to a server or client.
    # @param peer [Server,Client] The peer to send the packet to. Any class implementing {Connection} should work.
    def send(peer)

    end

    # Packets sent by servers with their list of other known servers.
    # - Request this packet with {Server#send_server_list_request}.
    # - Set a handler for these packets with {Core#handle_server_list}.
    class ServerList < Packet
      def initialize
        super(OP_EDONKEYPROT, OP_SERVERLIST)
      end
    end
  end
end
