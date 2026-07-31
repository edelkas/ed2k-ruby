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

    # The IP address of the node. Might be `nil` for clients if we haven't connected to them yet, or if they're not
    # reachable on the advertised port, since servers only share IP addresses of other clients whenever they are.
    # @return [String,nil]
    attr_reader :ip

    # The TCP port the node is listening to for incoming connections. Might be `nil` for clients if they're unreachable,
    # or when the hello handshake hasn't been done yet.
    # @return [Integer,nil]
    attr_reader :tcp_port

    # The UDP port this peer listens on, by convention its TCP port plus 4.
    # @return [Integer,nil]
    attr_reader :udp_port

    # The underlying `Socket` used by this connection.
    # @return [Socket]
    attr_reader :socket

    # The {Core} object responsible for this connection.
    # @return [Core]
    attr_reader :core

    # Whether this peer is ready to exchange TCP packets. This involves having a successful TCP connection established.
    # @note For **servers** you still have to log in (see {Server#send_login}) before being able to perform any other
    # operation. Similarly, for **clients** you still have to exchange hello packets (see {Client#send_hello}). You are
    # responsible for keeping track of this state.
    # @return [Boolean]
    attr_reader :ready_tcp

    # Whether this peer is ready to exchange UDP packets. Unlike TCP, this only involves having the address (IP and UDP port).
    # @return [Boolean]
    attr_reader :ready_udp

    # Whether this connection corresponds to a {Server}.
    # @note Servers will connect to us **as clients** after logging in to determine whether we're reachable or not. This
    # needs to be handled as a regular client connection, and is thus followed by exchanging {Packet::Hello}, so this
    # function will return `false` for those short-lived connections (not for the one we initiated).
    # @return [Boolean]
    def is_server?
      self.is_a?(ED2K::Server)
    end

    # Whether this connection corresponds to a {Client}.
    # @note (see {#is_server?})
    # @return [Boolean]
    def is_client?
      self.is_a?(ED2K::Client)
    end

    # Initialize the UDP-related resources of this connection. Unlike {#tcp_setup}, which prepares the per-connection TCP
    # socket and is called when a TCP connection is established, this is called once at construction because UDP traffic
    # (e.g. global server queries) can happen without ever establishing a TCP connection. There are no partial-data
    # buffers since UDP datagrams are self-contained. The UDP address is derived from the peer's IP and TCP port (+4).
    def udp_setup
      @udp_incoming_queue = Queue.new
      @udp_outgoing_queue = Queue.new
      @udp_port = @tcp_port ? @tcp_port + 4 : nil
      @pending_udp = 0
      @ready_udp = !!@udp_port
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

      # Current state of the connection. tcp_setup runs once the connection exists (we dialed out and it succeeded, or
      # we accepted an inbound one), so the peer is ready to exchange TCP packets from here on. Without this an accepted
      # connection would stay @ready_tcp = false and queue_tcp_packet would refuse to send to it.
      @ready_tcp = true
      @readable = true
      @writable = true

      # Buffers to hold incoming and outgoing data, usually partial packets
      @read_buffer  = ''
      @write_buffer = ''

      # Queues to hold complete incoming and outgoing packets
      @tcp_incoming_queue = Queue.new
      @control_queue  = Queue.new
      @standard_queue = Queue.new
    end

    # Attempt to establish a TCP connection with this server or client. This method should only be called when we're the
    # ones initiating the connection.
    # @note Do **not** call this method directly, use {Core#connect}. Otherwise, the core won't monitor the socket!
    # @param block [Boolean] Whether the connection should be attempted in a blocking or non-blocking way. In the latter
    # case, the function may be recalled multiple times until it returns `true`.
    # @param timeout [Float,Integer,nil] For blocking connections, the maximum number of seconds to wait before giving up
    # (returning `false`). `nil`, the default, waits indefinitely. Ignored for non-blocking connections.
    # @return [Boolean,nil] `true` if we're connected, `nil` if we're connecting, `false` if we failed to connect.
    # @todo This method DOESN'T add the connection to the set monitored by the core. FIX!
    #       Maybe most of these methods should be private.
    def connect(block = true, timeout: nil)
      # Ensure resouces (IP, TCP port, socket)
      lvl_inf = is_server?() ? Core::LOG_LEVEL_INFO : Core::LOG_LEVEL_DEBUG
      lvl_err = is_server?() ? Core::LOG_LEVEL_ERROR : Core::LOG_LEVEL_DEBUG
      if !@ip || !@tcp_port
        @core.log_error("Can't connect to #{format_name()}, missing IP address or TCP port")
        return false
      end
      if !@socket || @socket.closed?
        @core.log("Connecting to #{format_name()}...", lvl_inf)
        @socket = Socket.new(:INET, :STREAM)
      end
      sockaddr = Socket.sockaddr_in(@tcp_port, @ip)

      # Non-blocking connect
      return @socket.connect_nonblock(sockaddr) == 0 if !block

      # Blocking connect, w/ and w/o timeout
      if timeout
        begin
          @socket.connect_nonblock(sockaddr)
        rescue IO::WaitWritable
          # Connection underway: wait until the socket settles or 'timeout' seconds elapse. The socket goes into the
          # error set on failure (which is how Windows reports it, rather than as writable), so we pass it there too.
          unless IO.select(nil, [@socket], [@socket], timeout)
            @core.log("Timed out connecting to #{format_name()}", lvl_err)
            discard_socket()
            return false
          end
          # The attempt finished. SO_ERROR is 0 on success or the connect() error otherwise; reading it is portable,
          # unlike re-issuing connect_nonblock, which loops forever on a failed connect on Windows.
          if @socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int != 0
            @core.log("Failed to connect to #{format_name()}", lvl_err)
            discard_socket()
            return false
          end
        end
      else
        @socket.connect(sockaddr)
      end

      # Connected successfully
      @core.log("Connected to #{format_name()}", lvl_inf)
      tcp_setup()
      @ready_tcp = true
    rescue Errno::EISCONN
      # We are connected
      if !@ready_tcp
        @core.log("Connected to #{format_name()}", lvl_inf)
        tcp_setup()
        @ready_tcp = true
      end
      true
    rescue Errno::EINPROGRESS, Errno::EALREADY, Errno::EWOULDBLOCK
      # Connection in progress
      nil
    rescue Errno::ECONNREFUSED
      # The host is unreachable
      @core.log("Failed to connect to #{format_name()}", lvl_err)
      discard_socket()
      false
    rescue
      # Some other connection error
      @core.log("Unknown error connecting to #{format_name()}", lvl_err)
      discard_socket()
      false
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
      @socket.close if @socket
      @socket = nil

      @ready_tcp = false
    end

    # Discard a socket whose connection attempt never succeeded. Unlike {#disconnect}, this doesn't shut the socket
    # down or clear the R/W buffers and packet queues: none of those exist yet, since {#tcp_setup} only runs once a
    # connection is established. In particular, `shutdown` is skipped on purpose, as it raises `Errno::ENOTCONN` on a
    # socket that was never connected. This just closes the raw socket and marks us disconnected.
    def discard_socket
      @socket.close if @socket && !@socket.closed?
      @socket = nil
      @ready_tcp = false
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
      @socket.shutdown(Socket::SHUT_RD) if @socket
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
      @socket.shutdown(Socket::SHUT_WR) if @socket
      @write_buffer.clear
      @standard_queue.clear
      @control_queue.clear
      @standard_queue.close
      @control_queue.close
    end

    # Write a certain amount of data from the write buffer and the packet queues to the socket. Any packet that is popped
    # from the outgoing queues and not sent completely will remain in the buffer for the next call.
    # @param max [Integer] Maximum amount of bytes to put on the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually writen to the socket, -1 if the socket is closed or broken.
    def write(max)
      sent = 0

      # Finish any outstanding packets
      if !@write_buffer.empty?
        sent += write_buffered(max - sent)
        return sent if !@write_buffer.empty?
      end

      # Send as many control packets as possible
      while sent < max && !@control_queue.empty?
        @write_buffer = @control_queue.pop
        sent += write_buffered(max - sent)
        return sent if !@write_buffer.empty?
      end

      # Send as many data packets as possible
      while sent < max && !@standard_queue.empty?
        @write_buffer = @standard_queue.pop
        sent += write_buffered(max - sent)
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
      # The peer is gone, so tear down both ends rather than only the write side, letting the socket thread's alive?
      # reaper fully disconnect once any received packets are processed (see the matching branch in #read).
      close_for_writing()
      close_for_reading()
      sent == 0 ? -1 : sent
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
      sent == 0 ? -1 : sent
    ensure
      @core.stats[:out_data] += sent
    end

    # Push as much of the write buffer onto the socket as the budget allows, keeping whatever didn't fit for the next
    # call. The buffer is handed over whole whenever it fits within the budget, which is the common case, so that the
    # usual outgoing packet isn't copied just to be trimmed to a size it already respects.
    # @param max [Integer] Maximum amount of bytes to put on the socket.
    # @return [Integer] Amount of bytes actually written to the socket.
    def write_buffered(max)
      total = @write_buffer.bytesize
      written = @socket.write_nonblock(total <= max ? @write_buffer : @write_buffer.byteslice(0, max))
      @write_buffer = written == total ? '' : @write_buffer.byteslice(written, total - written)
      written
    end

    # Read a certain amount of data from the socket into the read buffer. Any complete packet will be pushed into the
    # incoming packet queue, and the remaining incomplete data will stay in the buffer for the next call.
    # @param max [Integer] Maximum amount of bytes to read from the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually read from the socket, -1 if `EOF` was reached, or the socket is closed or broken.
    def read(max)
      received = @read_buffer.size

      # Read as much as possible from the socket immediately
      @read_buffer << @socket.read_nonblock(max)
      received = @read_buffer.size - received

      # Push complete packets into the incoming queue.
      count, offset, total = 0, 0, @read_buffer.size
      while total - offset >= PACKET_HEADER_SIZE
        protocol, size, opcode = @read_buffer.unpack('CL<C', offset: offset)
        size -= 1 # Size field includes opcode, but opcode is part of header
        break if total - offset < PACKET_HEADER_SIZE + size
        @tcp_incoming_queue.push(@read_buffer.byteslice(offset, PACKET_HEADER_SIZE + size))
        offset += PACKET_HEADER_SIZE + size
        count += 1
      end

      # Wake up packet thread if packets were pushed. This costs CPU, so don't overdo it.
      if offset > 0
        @read_buffer = @read_buffer.byteslice(offset, total - offset)
        @core.schedule_packet(self, :tcp, count)
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
      # An EOF from an ed2k peer means they closed the whole socket (the protocol never half-closes), so tear down
      # both ends. Keeping only the read side closed would leave the connection writable, monitored and flagged as
      # ready forever, since alive? stays true while @writable is. Closing both lets the socket thread's alive? reaper
      # fully disconnect it once the already-received packets have been processed.
      close_for_reading()
      close_for_writing()
      -1
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      if self.is_a?(ED2K::Server)
        @core.log_error("Connection to server #{format_name()} was lost")
      else
        @core.log_debug("Connection was lost while reading from #{format_name()}")
      end
      close_for_reading()                  # A reset kills the whole socket, so drop both ends (see the EOF branch)
      close_for_writing()
      -1
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
      -1
    end

    # Queue an ed2k packet to be sent through the TCP socket.
    # @param protocol [Integer] A 1-byte integer specifying the protocol to use ({OP_EDONKEYPROT}, {OP_EMULEPROT}...)
    # @param opcode [Integer] A 1-byte integer specifying the operation to perform
    # @param payload [String] A (usually binary) string with the opcode-specific payload of the packet.
    # @param control [Boolean] Whether the packet is a control packet or a data (standard) packet.
    # @param wake [Boolean] Whether to wake the socket thread so it notices the packet right away instead of on its next
    #        round. Waking costs a syscall per call, which is well worth it for a control packet, whose whole point is to
    #        get out with minimal delay. It's a poor trade for data packets: they're queued in bulk, so the wakeups pile
    #        up while only the first one does anything useful, and the transfer is already running steadily enough for
    #        the socket thread to pick them up on its own. Defaults accordingly, but can be overridden either way, e.g.
    #        to flush a lone data packet promptly or to queue a batch of control packets and wake once at the end.
    # @param stop [Boolean] If `true`, the method will raise an exception when the TCP connection is not properly
    #   established yet. If `false` it'll simply return false.
    # @return [Boolean] Whether the packet was successfully queued in the corresponding packet queue or not.
    # @raise [StandardError] If the TCP connection isn't properly established.
    def queue_tcp_packet(protocol, opcode, payload = '', control = true, wake: control, stop: true)
      # Ensure connection is ready and resources are available
      if !@ready_tcp
        return false unless stop
        raise "Cannot queue TCP packet, TCP connection not ready, did you connect?"
      end
      queue = control ? @control_queue : @standard_queue
      return false if queue.closed?

      # Serialize packet, notify socket thread and log
      queue.push(payload.prepend([protocol, payload.size + 1, opcode].pack('CL<C')))
      @core.wake_socket_thread() if wake
      @core.stats[:out_packets] += 1
      @core.log_debug{ "Sent packet %#04x with protocol %#04x of size %d to %s" % [opcode, protocol, payload.size, format_name()] }
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
      return false if !@ready_udp
      size = payload.size
      @udp_outgoing_queue.push(payload.prepend([protocol, opcode].pack('CC')))
      @core.schedule_udp_send(self)
      @pending_udp += 1
      @core.stats[:out_packets] += 1
      @core.log_debug{ "Sent UDP packet %#04x with protocol %#04x of size %d to %s" % [opcode, protocol, size, format_name()] }
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
      payload = packet.byteslice(head, size) # Taking the payload out is cheaper than shifting it over the header

      # Parse packet - depending on protocol - and obtain opcode-specific packet data
      data = case protocol
      when OP_EDONKEYPROT
        parse_edonkey_tcp_packet(opcode, payload)
      when OP_EMULEPROT, OP_PACKEDPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT
        @core.log_debug{"Received unsupported ed2k protocol #{protocol}"}
        @core.run_handler(HAND_UNSUPPORTED_PROTOCOL, self, Packet::Raw.new(protocol, opcode, payload))
        return true
      else
        @core.run_handler(HAND_UNKNOWN_PROTOCOL, self, Packet::Raw.new(protocol, opcode, payload))
        raise "Received unknown ed2k protocol #{protocol}"
      end

      # Run the custom handler
      if !data
        @core.run_handler(HAND_CORRUPT_PACKET, self, Packet::Raw.new(protocol, opcode, payload))
        raise "Received corrupt TCP packet %#.2x for protocol %#.2x from #{format_name()}" % [opcode, protocol]
      elsif data.is_a?(Packet::Raw)
        @core.log_debug{ "Received unsupported TCP packet %#.2x for protocol %#.2x from #{format_name()}" % [opcode, protocol] }
        @core.run_handler(HAND_UNSUPPORTED_OPCODE, self, data)
      else
        @core.run_tcp_handler(protocol, opcode, self, data)
      end
      true
    rescue RuntimeError => e
      @core.log_debug{ e.message }
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
      payload = packet.byteslice(UDP_PACKET_HEADER_SIZE, length - UDP_PACKET_HEADER_SIZE)

      # Parse packet - depending on protocol - and obtain opcode-specific packet data
      data = case protocol
      when OP_EDONKEYPROT
        parse_edonkey_udp_packet(opcode, payload)
      when OP_EMULEPROT, OP_PACKEDPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT
        @core.log_debug("Received unsupported ed2k UDP protocol #{protocol}")
        @core.run_handler(HAND_UNSUPPORTED_PROTOCOL, self, Packet::Raw.new(protocol, opcode, payload))
        return true
      else
        @core.run_handler(HAND_UNKNOWN_PROTOCOL, self, Packet::Raw.new(protocol, opcode, payload))
        raise "Received unknown ed2k UDP protocol #{protocol}"
      end

      # Run the custom handler
      if !data
        @core.run_handler(HAND_CORRUPT_PACKET, self, Packet::Raw.new(protocol, opcode, payload))
        raise "Received corrupt UDP packet %#.2x for protocol %#.2x from #{format_name()}" % [opcode, protocol]
      elsif data.is_a?(Packet::Raw)
        @core.log_debug{ "Received unsupported UDP packet %#.2x for protocol %#.2x from #{format_name()}" % [opcode, protocol] }
        @core.run_handler(HAND_UNSUPPORTED_OPCODE, self, data)
      else
        @core.run_udp_handler(protocol, opcode, self, data)
      end
      true
    rescue RuntimeError => e
      @core.log_debug{ e.message }
      @core.stats[:in_packets_bad] += 1
      false
    end

  end # Connection

end
