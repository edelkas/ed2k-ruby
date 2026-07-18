module ED2K
 # Encapsulates the functionality that is common to each node connecting to the ed2k network, that is, both servers and
  # clients. It's a wrapper around a socket that manages I/O and its associated resources. Internally, each connection has
  # 2 buffers (for partial TCP reads and writes) as well as 5 thread-safe queues:
  #
  # - The **incoming TCP** queue stores ed2k packets as they are received from the socket.
  # - Similarly, an **incoming UDP** queue.
  # - The **standard** queue stores outgoing **TCP** data packets to send through the socket, i.e., the files being uploaded.
  #   They usually comprise the majority of the bandwidth.
  # - The **control** queue stores outgoing **TCP** control packets to send through the socket, i.e., any packet that is not
  #   data. They take precedence over data packets to minimize their delay.
  # - The **outgoing UDP** queue. All UDP packets are control packets, so there's no distinction here.
  #
  # Incoming packets are placed in the queue by the socket thread and processed by the packet thread. Conversely, outgoing
  # packets are placed in the queue by the packet thread, to be sent by the socket thread.
  # @todo Add integrity checks to the received packets (correct header...)
  module Connection

    # The address structure, containing info such as IP, port, socket type and protocol.
    # @return [Addrinfo]
    attr_reader :tcp_address

    # The address structure used to send UDP datagrams to this peer, if known. By convention its port is the peer's TCP
    # port plus 4. May be `nil` if we don't (yet) know the peer's IP or port.
    # @return [Addrinfo,nil]
    attr_reader :udp_address

    # The UDP port this peer listens on, by convention its TCP port plus 4. May be `nil` if the peer's port is unknown.
    # @return [Integer,nil]
    attr_reader :udp_port

    # The underlying `Socket` used by this connection.
    # @return [Socket]
    attr_reader :socket

    # The {Core} object responsible for this connection.
    # @return [Core]
    attr_reader :core

    # Initialize the UDP-related resources of this connection. Unlike {#tcp_setup}, which prepares the per-connection TCP
    # socket and is called when a TCP connection is established, this is called once at construction because UDP traffic
    # (e.g. global server queries) can happen without ever establishing a TCP connection. There are no partial-data
    # buffers since UDP datagrams are self-contained. The UDP address is derived from the peer's IP and TCP port (+4).
    def udp_setup
      @udp_incoming_queue = Queue.new
      @udp_outgoing_queue = Queue.new
      @udp_port = @tcp_port ? @tcp_port + 4 : nil
      @udp_address = (@ip && @udp_port) ? Addrinfo.new(Socket.pack_sockaddr_in(@udp_port, @ip)) : nil
      @pending_udp = 0
    end

    # How many UDP queries we've sent to this peer that haven't been answered yet. Peers essentially only send us
    # datagrams in response to our own queries, so this is used as a hint to tell apart several servers sharing a
    # single IP address when a datagram arrives from that address (see {Core#get_server}).
    # @return [Boolean] Whether we're awaiting at least one UDP answer from this peer.
    def pending_udp?
      @pending_udp > 0
    end

    # Note that a datagram we were waiting for has arrived, so it no longer counts as pending. Datagrams are
    # best-effort and answers may never come, so the counter is only ever decremented down to zero.
    def udp_answered
      @pending_udp -= 1 if @pending_udp > 0
    end

    # Initialize resources to prepare communication. This includes R/W buffers, packet queues and state variables.
    # Must be called once before exchanging messages with a server/client, usually right before or after establishing
    # a connection.
    # @param socket [Socket] The socket to communicate through, when the peer is the one that connected to us and thus
    #        we didn't open it ourselves. Note that the peer's address is deliberately left untouched, since the port
    #        they're connecting to us from isn't the one they listen on.
    def tcp_setup(socket = nil)
      @socket = socket if socket

      # Current state of the connection
      @readable = true
      @writable = true

      # Buffers to hold incoming and outgoing data, usually partial packets
      @read_buffer  = ''
      @write_buffer = ''

      # Queues to hold complete incoming and outgoing packets
      @tcp_incoming_queue = Queue.new
      @control_queue  = Queue.new
      @standard_queue = Queue.new

      @ready = true
    end

    # Attempt to establish a TCP connection in a non-blocking way. May be recalled multiple times until we manage to
    # get a connection. Should only be called when we're the ones initiating the connection.
    # @return [Boolean,nil] `true` if we're connected, `nil` if we're connecting, `false` if we failed to connect.
    def connect
      tcp_setup()
      if !@socket || @socket.closed?
        @core.log_debug("Connecting to #{format_name()}...")
        @socket = Socket.new(:INET, :STREAM)
      end
      @socket.connect_nonblock(@tcp_address) == 0
    rescue Errno::EISCONN
      @core.log_debug("Connected to #{format_name()}")
      true   # We are connected
    rescue Errno::EINPROGRESS, Errno::EALREADY, Errno::EWOULDBLOCK
      nil    # Connection in progress
    rescue Errno::ECONNREFUSED
      @core.log_debug("Failed to connect to #{format_name()}")
      false  # The host is unreachable
    rescue
      @core.log_debug("Unknown error connecting to #{format_name()}")
      false  # Some other connection error
    end

    # Close the underlying socket and free all the resources (system socket, internal R/W buffers, packet queues...)
    # @note This clears the incoming packet queue, so it should only be called when we we've finished processing it or
    #       we no longer care about what's in there.
    def disconnect
      # Shutdown each socket end, stop monitoring it for reading or writing,
      # and clear the buffers and packet queues
      close_for_reading(true)
      close_for_writing()

      # Close underlying connection
      @core.log_debug("Disconnected from #{format_name()}")
      @socket.close
      @socket = nil
    end

    # Whether we can read from the socket. In that case, we always monitor it.
    # @return [Boolean] `true` if the socket is open for reading, `false` otherwise.
    def ready_for_reading
      @readable
    end

    # Whether we have something to write to the socket, and thus should monitor it
    # @return [Boolean] `true` if the write buffer or outgoing queues aren't empty, `false` otherwise.
    def ready_for_writing
      @writable && (!@write_buffer.empty? || !@control_queue.empty? || !@standard_queue.empty?)
    end

    # Whether at least one end of the socket (R/W) is still open and functioning, or we still have unfinished work with
    # this connection, such as processing received packets.
    def alive?
      @readable || @writable || !@tcp_incoming_queue.empty?
    end

    # Stop reading from the socket, usually called when the other end of the socket has stopped writing. This shuts down
    # the reading end of the socket and marks it to stop monitoring. It also clears the read buffer, as anything still in
    # there is an incomplete packet and may be safely discarded. Optionally also clears the incoming packet queue,
    # although this can be maintained in order to finish processing them later.
    # @param clear [Boolean] If `true` then the read buffer and queue is cleared, otherwise they're kept.
    def close_for_reading(clear = false)
      @readable = false
      @socket.shutdown(Socket::SHUT_RD)
      return if !clear
      @read_buffer.clear
      @tcp_incoming_queue.clear
      @tcp_incoming_queue.close
    end

    # Stop writing to a socket, called when the other end of the socket has stopped reading, or when we are done writing.
    # This shuts down the writing end of the socket and marks it to stop monitoring. It also clears the write buffer and
    # the outgoing packet queues, anything in there not sent is discarded.
    def close_for_writing
      @writable = false
      @socket.shutdown(Socket::SHUT_WR)
      @write_buffer.clear
      @standard_queue.clear
      @control_queue.clear
      @standard_queue.close
      @control_queue.close
    end

    # Write a certain amount of data from the write buffer and the packet queues to the socket. Any packet that is popped
    # from the outgoing queues and not sent completely will remain in the buffer for the next call.
    # @todo Can we prevent so much string slicing here?
    # @param max [Integer] Maximum amount of bytes to put on the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually writen to the socket, -1 if the socket is closed or broken.
    def write(max)
      sent, written = 0, 0

      # Finish any outstanding packets
      if !@write_buffer.empty?
        sent += written = @socket.write_nonblock(@write_buffer[0, max - sent])
        @write_buffer.slice!(0, written)
        return sent if !@write_buffer.empty?
      end

      # Send as many control packets as possible
      while sent < max && !@control_queue.empty?
        @write_buffer = @control_queue.pop
        sent += written = @socket.write_nonblock(@write_buffer[0, max - sent])
        @write_buffer.slice!(0, written)
        return sent if !@write_buffer.empty?
      end

      # Send as many data packets as possible
      while sent < max && !@standard_queue.empty?
        @write_buffer = @standard_queue.pop
        sent += written = @socket.write_nonblock(@write_buffer[0, max - sent])
        @write_buffer.slice!(0, written)
        return sent if !@write_buffer.empty?
      end

      sent
    rescue IO::WaitWritable                # Cannot write any more
      sent
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      if self.is_a?(ED2K::Server)
        @core.log_error("Connection to server #{format_name()} was lost")
      else
        @core.log_debug("Connection was lost while writing to #{format_name()}")
      end
      close_for_writing()
      sent == 0 ? -1 : sent
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
      sent == 0 ? -1 : sent
    ensure
      @core.stats[:out_data] += sent
    end

    # Read a certain amount of data from the socket into the read buffer. Any complete packet will be pushed into the
    # incoming packet queue, and the remaining incomplete data will stay in the buffer for the next call.
    # @todo Can we prevent so much string slicing here?
    # @param max [Integer] Maximum amount of bytes to read from the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually read from the socket, -1 if `EOF` was reached, or the socket is closed or broken.
    def read(max)
      received = @read_buffer.size

      # Read as much as possible from the socket immediately
      @read_buffer << @socket.read_nonblock(max)
      received = @read_buffer.size - received

      # Push complete packets into the incoming queue
      while @read_buffer.size >= PACKET_HEADER_SIZE
        protocol, size, opcode = @read_buffer.unpack('CL<C')
        size -= 1 # Size field includes opcode, but opcode is part of header
        break if @read_buffer.size < PACKET_HEADER_SIZE + size
        @tcp_incoming_queue.push(@read_buffer.slice!(0, PACKET_HEADER_SIZE + size))
        @core.schedule_packet(self)
      end

      @core.stats[:in_data] += received
      received
    rescue IO::WaitReadable                # Nothing to read
      0
    rescue EOFError                        # Peer stopped writing
      if self.is_a?(ED2K::Server)
        @core.log_error("Server #{format_name()} closed the connection")
      else
        @core.log_debug("EOF received from #{format_name()}")
      end
      close_for_reading()
      -1
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      if self.is_a?(ED2K::Server)
        @core.log_error("Connection to server #{format_name()} was lost")
      else
        @core.log_debug("Connection was lost while reading from #{format_name()}")
      end
      close_for_reading()
      -1
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
      -1
    end

    # Queue an ed2k packet to be sent through the TCP socket.
    # @param protocol [Integer] A 1-byte integer specifying the protocol to use ({OP_EDONKEYPROT}, {OP_EMULEPROT}...)
    # @param opcode [Integer] A 1-byte integer specifying the operation to perform
    # @param payload [String] A (usually binary) string with the opcode-specific payload of the packet.
    # @param control [Boolean] Whether the packet is a control packet or a data (standard) packet.
    # @return [Boolean] Whether the packet was successfully queued in the corresponding packet queue or not.
    def queue_tcp_packet(protocol, opcode, payload = '', control = true)
      queue = control ? @control_queue : @standard_queue
      return false if queue.closed?
      queue.push(payload.prepend([protocol, payload.size + 1, opcode].pack('CL<C')))
      @core.wake_socket_thread()
      @core.stats[:out_packets] += 1
      @core.log_debug("Sent packet %#04x with protocol %#04x of size %d to %s" % [opcode, protocol, payload.size, format_name()])
      @core.log_trace(payload)
      true
    end

    # Queue an ed2k packet to be sent to this peer through the shared UDP socket. Unlike {#queue_tcp_packet} there is no
    # control/data distinction (all UDP traffic is control) and the header carries no size field. Fails if we don't know
    # the peer's UDP address yet.
    # @param protocol [Integer] A 1-byte integer specifying the protocol to use ({OP_EDONKEYPROT}, {OP_EMULEPROT}...)
    # @param opcode [Integer] A 1-byte integer specifying the operation to perform
    # @param payload [String] A (usually binary) string with the opcode-specific payload of the packet.
    # @return [Boolean] Whether the packet was successfully queued for sending or not.
    def queue_udp_packet(protocol, opcode, payload = '')
      return false if !@udp_address
      size = payload.size
      @udp_outgoing_queue.push(payload.prepend([protocol, opcode].pack('CC')))
      @core.schedule_udp_send(self)
      @pending_udp += 1
      @core.stats[:out_packets] += 1
      @core.log_debug("Sent UDP packet %#04x with protocol %#04x of size %d to %s" % [opcode, protocol, size, format_name()])
      @core.log_trace(payload)
      true
    end

    # Pop the next queued outgoing UDP datagram, or `nil` if there is none. Called by the socket thread once per send token.
    # @return [String,nil] The raw datagram to send, or `nil` if the queue is empty.
    def dequeue_outgoing_udp
      @udp_outgoing_queue.pop(true)
    rescue ThreadError # Queue empty: stale token for an already-drained connection
      nil
    end

    # Put a datagram back on the outgoing UDP queue, used when the send buffer was full and the send must be retried. Order
    # is not preserved, which is fine since UDP delivery is unordered anyway.
    # @param packet [String] The raw datagram that could not be sent.
    def requeue_outgoing_udp(packet)
      @udp_outgoing_queue.push(packet)
    end

    # Process a new incoming packet and run the corresponding handler
    # @param packet [String] A binary string containing the raw packet data
    # @return [Boolean] Whether the packet was parsed and processed successfully or not
    def process_tcp_packet(packet)
      # Sanity checks
      @core.stats[:in_packets] += 1
      head = PACKET_HEADER_SIZE
      length = packet.length
      raise "Incorrect packet length (#{length} < #{head})" if length < head
      protocol, size, opcode = packet.unpack('CL<C')
      size -= 1
      raise "Incorrect packet length (#{length} vs #{head + size})" if length != head + size
      packet.slice!(0, head)

      # Parse packet - depending on protocol - and obtain opcode-specific packet data
      case protocol
      when OP_EDONKEYPROT
        data = parse_edonkey_tcp_packet(opcode, packet)
      when OP_EMULEPROT
        data = parse_emule_tcp_packet(opcode, packet)
      when OP_PACKEDPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT
        @core.log_debug("Received unsupported ed2k protocol #{protocol}")
        return true
      else
        raise "Received unknown ed2k protocol #{protocol}"
      end

      # Run the custom handler
      raise "Received corrupt package #{opcode} for protocol #{protocol}" if !data
      @core.run_tcp_handler(protocol, opcode, self, data)
      true
    rescue RuntimeError => e
      @core.log_debug(e.message)
      @core.stats[:in_packets_bad] += 1
      false
    end

    # Process a new incoming UDP packet and run the corresponding handler. Unlike {#process_tcp_packet}, the header has no size
    # field (the datagram boundary gives the length) and the opcodes are interpreted through the UDP-specific parsers and
    # handler registry, since UDP opcodes overlap the TCP ones but carry different meanings.
    # @param packet [String] A binary string containing the raw datagram
    # @return [Boolean] Whether the packet was parsed and processed successfully or not
    def process_udp_packet(packet)
      # Sanity checks
      @core.stats[:in_packets] += 1
      length = packet.length
      raise "Incorrect UDP packet length (#{length} < #{UDP_PACKET_HEADER_SIZE})" if length < UDP_PACKET_HEADER_SIZE
      protocol, opcode = packet.unpack('CC')
      packet.slice!(0, UDP_PACKET_HEADER_SIZE)

      # Parse packet - depending on protocol - and obtain opcode-specific packet data
      case protocol
      when OP_EDONKEYPROT
        data = parse_edonkey_udp_packet(opcode, packet)
      when OP_EMULEPROT
        data = parse_emule_udp_packet(opcode, packet)
      when OP_PACKEDPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT
        @core.log_debug("Received unsupported ed2k UDP protocol #{protocol}")
        return true
      else
        raise "Received unknown ed2k UDP protocol #{protocol}"
      end

      # Run the custom handler
      raise "Received corrupt UDP package #{opcode} for protocol #{protocol}" if !data
      @core.run_udp_handler(protocol, opcode, self, data)
      true
    rescue RuntimeError => e
      @core.log_debug(e.message)
      @core.stats[:in_packets_bad] += 1
      false
    end

    # Parse a packet sent by this peer with the standard edonkey protocol over UDP. Default no-op that reports the opcode
    # as unsupported; servers and clients override this to handle the UDP opcodes relevant to them.
    # @param opcode [Integer] The packet's identifying opcode.
    # @param packet [String] The packet's payload, without the header.
    # @return Packet-specific processed payload, or `nil` if processing failed or the opcode is unsupported.
    def parse_edonkey_udp_packet(opcode, packet)
      @core.log_debug("Received unsupported edonkey UDP packet %#.2x from #{format_name()}" % opcode)
      nil
    end

    # Parse a packet sent by this peer with the extended eMule protocol over UDP. Default no-op that reports the opcode as
    # unsupported; servers and clients override this to handle the UDP opcodes relevant to them.
    # @param opcode [Integer] The packet's identifying opcode.
    # @param packet [String] The packet's payload, without the header.
    # @return Packet-specific processed payload, or `nil` if processing failed or the opcode is unsupported.
    def parse_emule_udp_packet(opcode, packet)
      @core.log_debug("Received unsupported eMule UDP packet %#.2x from #{format_name()}" % opcode)
      nil
    end

    # Append a received UDP datagram to this connection's incoming UDP queue, to later be processed by the packet thread.
    # Called by the socket thread after it demultiplexes a datagram to this connection.
    # @param packet [String] A binary string containing the raw datagram
    def enqueue_incoming_udp(packet)
      @udp_incoming_queue.push(packet)
    end

    # Consumes and processes a single pending packet from one of the incoming queues, corresponding to one scheduling
    # token popped by the packet thread. The channel (:tcp or :udp) selects the queue and the parser. If the queue is
    # empty (e.g. it was cleared on disconnect and this is a stale token) the call is a harmless no-op.
    # @param channel [Symbol] Either :tcp or :udp, matching the queue the packet was scheduled on.
    # @return [Boolean] `true` if a packet was processed, `false` if there was none or it was invalid
    def process_one_packet(channel = :tcp)
      queue = channel == :udp ? @udp_incoming_queue : @tcp_incoming_queue
      packet = queue.pop(true)
      return false if !packet # nil means the queue was closed and drained (disconnected peer)
      channel == :udp ? process_udp_packet(packet) : process_tcp_packet(packet)
    rescue ThreadError # Queue empty but still open: stale token for an already-drained connection
      false
    end

  end # Connection

end
