module ED2K
  # A {Core} instance contains all necessary elements to operate your connection to the ed2k network. It manages the sockets,
  # communicates with servers and other clients, and handles the reception and sending of ed2k packets, running the appropriate
  # handlers whenever necessary.
  #
  # Under normal operation, you simply spin up a single core and keep a reference to it to control it. Nothing
  # prevents creating multiple cores but this does not provide any advantage, you can think of it as opening multiple
  # copies of eMule. Also, the IP addresses used by all cores would be the same, preventing connection to the same
  # server and possibly causing other issues.
  #
  # A running core consists of the following two threads:
  #
  # - The **socket thread** constantly monitors all open sockets for new R/W activity. When a full packet is received it's
  #   created and placed in the incoming queue, and when a full data block is received it's stored in the incoming buffer.
  #   Conversely, outgoing packets or data are serialized and sent through the corresponding socket.
  #
  # - The **packet thread** monitors the queues for new incoming or outgoing packets. When an incoming packet is received,
  #   it's processed and the corresponding actions are taken, including running the handlers. When an outgoing action is
  #   scheduled, the packet is created and placed in the socket queue.
  #
  # This separation ensures that operations handling packets or data do not block socket activity.
  class Core

    LOG_SIZE                 = 1000      # Number of messages to save in the log
    SOCKET_READ_SIZE         = 16 * 1024 # Maximum data in bytes to read from each socket in a single non-blocking call
    SOCKET_WRITE_SIZE        = 16 * 1024 # Maximum data in bytes to write to each socket in a single non-blocking call
    DEFAULT_THREAD_FREQUENCY = 0.05      # Minimum time in seconds between loop iterations of the core threads, for CPU throttling
    DEFAULT_THREAD_TIMEOUT   = 1         # Maximum time in seconds to wait for a loop iteration to finish when stopping a thread

    def initialize
      @init = false
      @log = []
      reload_preferences()

      # Init socket thread
      init_connections()
      @control_socket = TCPServer.new(@tcp_port)
      start_socket_thread()

      # Init packet thread
      @handlers = {}
      start_packet_thread()

      @init = true
    end

    # Read user preferences from disk and fill the missing ones with the default values
    def reload_preferences
      @tcp_port = DEFAULT_TCP_PORT
      @udp_port = DEFAULT_UDP_PORT
    end

    # Starts the socket thread and begins monitoring network IO.
    # @note This is done automatically by {#initialize}, only do manually if stopped manually or if it crashed.
    # @return [Thread] The socket thread object
    def start_socket_thread
      @thSockRun = true
      return @thSock if @thSock&.alive?
      @thSockFreq = DEFAULT_THREAD_FREQUENCY
      @thSockTick = Time.now
      @thSock = Thread.new{ run_socket_thread() }
    end

    # Starts the packet thread and begins monitoring incoming packets to be parsed
    # @note This is done automatically by {#initialize}, only do manually if stopped manually or if it crashed.
    # @return [Thread] The packet thread object
    def start_packet_thread
      @thPackRun = true
      return @thPack if @thPack&.alive?
      @thPackFreq = DEFAULT_THREAD_FREQUENCY
      @thPackTick = Time.now
      @thPack = Thread.new{ run_packet_thread() }
    end

    # Attempts to stop the socket thread gracefully and end network monitoring. It will wait until the current loop is
    # finished, which is normally very quick. It does **not** close the sockets afterwards.
    # @note This is done automatically when disconnecting.
    # @see #kill_socket_thread
    # @return [Boolean] `true` if the thread was stopped successfully, `false` if it wasn't running or failed to be stopped.
    def stop_socket_thread
      return false if !@thSock&.alive?
      @thSockRun = false
      return false if !@thSock.join(DEFAULT_THREAD_TIMEOUT)
      @thSock.kill
      true
    end

    # Attempts to stop the packet thread gracefully and end packet parsing. It will wait until the current loop is
    # finished, which is normally very quick.
    # @note This is done automatically when disconnecting.
    # @see #kill_packet_thread
    # @return [Boolean] `true` if the thread was stopped successfully, `false` if it wasn't running or failed to be stopped.
    def stop_packet_thread
      return false if !@thPack&.alive?
      @thPackRun = false
      return false if !@thPack.join(DEFAULT_THREAD_TIMEOUT)
      @thPack.kill
      true
    end

    # Forcefully kill the socket thread and stop network monitoring. It does **not** close the sockets afterwards.
    # @see #stop_socket_thread
    # @return [Boolean] `true` if the thread was killed, `false` if it wasn't running.
    def kill_socket_thread
      return false if !@thSock&.alive?
      @thSockRun = false
      @thSock.kill
      true
    end

    # Forcefully kill the packet thread and stop packet parsing.
    # @see #stop_packet_thread
    # @return [Boolean] `true` if the thread was killed, `false` if it wasn't running.
    def kill_packet_thread
      return false if !@thPack&.alive?
      @thPackRun = false
      @thPack.kill
      true
    end

    # Add a message to the log of this core.
    # @param msg [String] Text to log.
    def log(msg)
      @log << msg
      @log.shift if @log.length > LOG_SIZE
      puts "[%s %s]" % [Time.now.strftime('%H:%M:%S'), msg]
    end

    private

    # Socket thread permanently monitors sockets for R/W activity
    def run_socket_thread
      while @thSockRun
        # Block until next socket activity
        to_read  = @connections.values.select(&:ready_for_reading).map(&:socket)
        to_write = @connections.values.select(&:ready_for_writing).map(&:socket)
        to_read.push(@control_socket)
        readable, writable = IO.select(to_read, to_write)

        # Read from sockets
        readable.each do |socket|
          # New incoming connection, accept it
          next add_connection(socket.accept) if socket == @control_socket

          # Server or client activity, read data
          connection = @connections[socket.fileno]
          read = connection.read(SOCKET_READ_SIZE)
        end

        # Write to sockets
        writable.each do |socket|
          connection = @connections[socket.fileno]
          written = connection.write(SOCKET_WRITE_SIZE)
        end

        # Ditch dead sockets
        @connections.each do |conn|
          remove_connection(conn) if !conn.alive?
        end

        # Prepare next iteration
        current_time = Time.now
        elapsed = current_time - @thSockTick
        @thSockTick = current_time
        sleep(@thSockFreq - elapsed) if elapsed < @thSockFreq
      end
    end

    # Packet thread monitors the incoming packet queue for new received packets to parse and process
    def run_packet_thread
      while @thPackRun
        # Consume all new packets
        @connections.each do |conn|
          conn.process_packets
        end

        # Prepare next iteration
        current_time = Time.now
        elapsed = current_time - @thPackTick
        @thPackTick = current_time
        sleep(@thPackFreq - elapsed) if elapsed < @thPackFreq
      end
    end

    # Initialize the structure storing all connections that need to be monitored for either read or write activity.
    # We use a hash keyed on the underlying socket's file descriptor.
    def init_connections
      @connections = {}
    end

    # Create a new connection and add it for IO monitoring
    def add_connection(socket)
      @connections[socket.fileno] = Connection.new(socket, self)
    end

    # Stop monitoring a connection and remove the reference to it
    def remove_connection(conn)
      conn.destroy
      @connections.delete(conn.socket.fileno)
    end

  end # Core

  # Wrapper around a socket that manages I/O and its associated resources. Internally, each connection has 2 buffers
  # (read and write) as well as 3 thread-safe queues:
  #
  # - The **incoming** queue stores ed2k packets as they are received from the socket.
  # - The **standard** queue stores outgoing data packets to send through the socket, i.e., the files being uploaded.
  #   They usually comprise the majority of the bandwidth.
  # - The **control** queue stores outgoing control packets to send through the socket, i.e., any packet that is not
  #   data. They take precedence over data packets to minimize their delay.
  #
  # Incoming packets are placed in the queue by the socket thread and processed by the packet thread. Conversely, outgoing
  # packets are placed in the queue by the packet thread, to be sent by the socket thread.
  # @todo Add integrity checks to the received packets (correct header...)
  class Connection

    # The underlying `Socket` used by this connection.
    # @return [Socket]
    attr_reader :socket

    # The {Core} object responsible for this connection.
    # @return [Core]
    attr_reader :core

    # @param socket [Socket] The underlying `Socket` object handling this connection.
    def initialize(socket, core)
      # Underlying system socket, and core container this connection belongs to
      @socket = socket
      @core   = core

      # Current state of the connection
      @readable = true
      @writable = true

      # Buffers to hold incoming and outgoing data, usually partial packets
      @read_buffer  = ''
      @write_buffer = ''

      # Queues to hold incoming and outgoing packets
      @incoming_queue = Queue.new
      @control_queue  = Queue.new
      @standard_queue = Queue.new
    end

    # Close the underlying socket and free all the resources (system socket, internal R/W buffers, packet queues...)
    # @note This clears the incoming packet queue, so it should only be called when we we've finished processing it or
    #       we no longer care about what's in there.
    def destroy
      # Shutdown each socket end, stop monitoring it for reading or writing,
      # and clear the buffers and packet queues
      close_for_reading(true)
      close_for_writing()

      # Close underlying connection
      @socket.close
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
      @readable || @writable || !@incoming_queue.empty?
    end

    # Stop reading from the socket, usually called when the other end of the socket has stopped writing. This shuts down
    # the reading end of the socket and marks it to stop monitoring. It also clears the read buffer, as anything still in
    # there is an incomplete packet and may be safely discarded. Optionally also clears the incoming packet queue,
    # although this can be maintained in order to finish processing them later.
    # @param clear [Boolean] If `true` then the read buffer and queue is cleared, otherwise they're kept.
    # @return [Boolean] `true` if the connection has been closed for reading, `false` if it was already closed.
    def close_for_reading(clear = false)
      return false if !@readable
      @readable = false
      @socket.shutdown(Socket::SHUT_RD)
      @read_buffer.clear
      return true if !clear
      @incoming_queue.clear
      @incoming_queue.close
      true
    end

    # Stop writing to a socket, called when the other end of the socket has stopped reading, or when we are done writing.
    # This shuts down the writing end of the socket and marks it to stop monitoring. It also clears the write buffer and
    # the outgoing packet queues, anything in there not sent is discarded.
    # @return [Boolean] `true` if the connection has been closed for writing, `false` if it was already closed.
    def close_for_writing
      return false if !@writable
      @writable = false
      @socket.shutdown(Socket::SHUT_WR)
      @write_buffer.clear
      @standard_queue.clear
      @control_queue.clear
      @standard_queue.close
      @control_queue.close
      true
    end

    # Write a certain amount of data from the write buffer and the packet queues to the socket. Any packet that is popped
    # from the outgoing queues and not sent completely will remain in the buffer for the next call.
    # @todo Can we prevent so much string slicing here?
    # @param max [Integer] Maximum amount of bytes to put on the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually writen to the socket.
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
    rescue IO::WaitWritable # Cannot write any more
      sent
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      close_for_writing()
      sent
    end

    # Read a certain amount of data from the socket into the read buffer. Any complete packet will be pushed into the
    # incoming packet queue, and the remaining incomplete data will stay in the buffer for the next call.
    # @todo Can we prevent so much string slicing here?
    # @param max [Integer] Maximum amount of bytes to read from the socket. Useful for bandwidth management.
    # @return [Integer] Total amount of bytes actually read from the socket. If `EOF` or the socket was closed, returns -1.
    def read(max)
      received = @read_buffer.size

      # Read as much as possible from the socket immediately
      @read_buffer << @socket.read_nonblock(max)
      received = @read_buffer.size - received

      # Push complete packets into the incoming queue
      while @read_buffer.size >= PACKET_HEADER_SIZE
        protocol, size, opcode = @read_buffer.unpack('CL<C')
        break if @read_buffer.size < PACKET_HEADER_SIZE + size
        @incoming_queue.push(@read_buffer.slice!(0, PACKET_HEADER_SIZE + size))
      end

      received
    rescue IO::WaitReadable # Nothing to read
      0
    rescue EOFError # Peer stopped writing
      close_for_reading()
      -1
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      close_for_reading()
      -1
    end

    # Queue an ed2k packet to be sent through the socket.
    # @param protocol [Integer] A 1-byte integer specifying the protocol to use ({OP_EDONKEYPROT}, {OP_EMULEPROT}...)
    # @param opcode [Integer] A 1-byte integer specifying the operation to perform
    # @param payload [String] A (usually binary) string with the opcode-specific payload of the packet.
    # @param control [Boolean] Whether the packet is a control packet or a data (standard) packet.
    # @return [Boolean] Whether the packet was successfully queued in the corresponding packet queue or not.
    def queue_packet(protocol, opcode, payload, control = true)
      queue = control ? @control_queue : @standard_queue
      return false if queue.closed?
      queue.push(payload.prepend([protocol, payload.size, opcode].pack('CL<C')))
      true
    end

    # Process a new incoming packet and run the corresponding handler
    # @param packet [String] A binary string containing the raw packet data
    # @return [Boolean] Whether the packet was parsed and processed successfully or not
    def process_packet(packet)
      # Sanity checks
      length = packet.length
      return false if length < PACKET_HEADER_SIZE
      protocol, size, opcode = packet.unpack('CL<C')
      return false if length != PACKET_HEADER_SIZE + size
      packet.slice!(0, PACKET_HEADER_SIZE)

      # Parse packet - depending on protocol - and obtain opcode-specific packet data
      case protocol
      when OP_EDONKEYPROT
        data = parse_edonkey_packet(opcode, packet)
      when OP_EMULEPROT
        data = parse_emule_packet(opcode, packet)
      when OP_PACKEDPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT
        @core.log("Received unsupported ed2k protocol #{protocol}")
        return true
      else
        @core.log("Received unknown ed2k protocol #{protocol}")
        return false
      end

      # Run the custom handler
      @core.handlers[protocol][opcode].call(data)
    end

    # Consumes and processes all the currently pending packets from the incoming queue
    # @return [Integer] Amount of successfully processed packets in this call
    def process_packets
      packets = 0
      loop do
        packet = @incoming_queue.pop(true)
        packets += 1 if process_packet(packet)
      end
      packets
    rescue ThreadError
      packets
    end

  end # Connection

end # ED2K
