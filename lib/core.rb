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
      @servers = {}
      @clients = {}
      reload_preferences()

      # Init socket thread
      init_connections()
      @control_socket = TCPServer.new(@tcp_port)
      start_socket_thread()

      # Init packet thread
      @handlers = {}
      start_packet_thread()

      @init = true
      log("Initialized core")
    end

    # Read user preferences from disk and fill the missing ones with the default values
    def reload_preferences
      @tcp_port = DEFAULT_TCP_PORT
      @udp_port = DEFAULT_UDP_PORT
      log("Loaded preferences")
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
      log("Started socket thread")
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
      log("Started packet thread")
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

    # Get a known client by address. Only one of the parameters needs to be specified.
    # @param address [Addrinfo] The full address structure of the client.
    # @param ip [String] The IPv4 address of the client.
    # @return [Client,nil] The client object if known, `nil` otherwise.
    def get_client(address: nil, ip: nil)
      @clients[IPAddr.new(ip || address.ip_address).to_i]
    end

    # Get a known server by address. Only one of the parameters needs to be specified.
    # @param address [Addrinfo] The full address structure of the server.
    # @param ip [String] The IPv4 address of the server.
    # @return [Server,nil] The server object if known, `nil` otherwise.
    def get_server(address: nil, ip: nil)
      @servers[IPAddr.new(ip || address.ip_address).to_i]
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
      addr = socket.remote_address
      ip = "%s:%d" % [addr.ip_address, addr.ip_port]
      if host = get_server(address: addr)
        log("Received new incoming connection from known server #{ip}")
      elsif host = get_client(address: addr)
        log("Received new incoming connection from known client #{ip}")
      else
        log("Found new client #{ip}")
        host = Client.new(socket: socket, core: self)
      end
      host.setup
      @connections[socket.fileno] = host
    end

    # Stop monitoring a connection and remove the reference to it
    def remove_connection(conn)
      conn.disconnect
      @connections.delete(conn.socket.fileno)
    end

  end # Core

  # Encapsulates the functionality that is common to each node connecting to the ed2k network, that is, both servers and
  # clients. It's a wrapper around a socket that manages I/O and its associated resources. Internally, each connection has
  # 2 buffers (read and write) as well as 3 thread-safe queues:
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
  module Connection

    # The address structure, containing info such as IP, port, socket type and protocol.
    # @return [Addrinfo]
    attr_reader :address

    # The underlying `Socket` used by this connection.
    # @return [Socket]
    attr_reader :socket

    # The {Core} object responsible for this connection.
    # @return [Core]
    attr_reader :core

    # Initialize resources to prepare communication. This includes R/W buffers, packet queues and state variables.
    # Must be called once before exchanging messages with a server/client, usually right before or after establishing
    # a connection.
    def setup
      # Current state of the connection
      @readable = true
      @writable = true

      # Buffers to hold incoming and outgoing data, usually partial packets
      @read_buffer  = ''
      @write_buffer = ''

      # Queues to hold complete incoming and outgoing packets
      @incoming_queue = Queue.new
      @control_queue  = Queue.new
      @standard_queue = Queue.new

      @ready = true
    end

    # Attempt to establish a TCP connection in a non-blocking way. May be recalled multiple times until we manage to
    # get a connection. Should only be called when we're the ones initiating the connection.
    # @return [Boolean,nil] `true` if we're connected, `nil` if we're connecting, `false` if we failed to connect.
    def connect
      setup() if !@ready
      @socket = Socket.new(:INET, :STREAM) if !@socket || @socket.closed?
      @core.log("Connecting to #{format_name()}...")
      @socket.connect_nonblock(@address) == 0
    rescue Errno::EISCONN
      @core.log("Connected to #{format_name()}")
      true   # We are connected
    rescue Errno::EINPROGRESS, Errno::EALREADY, Errno::EWOULDBLOCK
      nil    # Connection in progress
    rescue Errno::ECONNREFUSED
      @core.log("Failed to connect to #{format_name()}")
      false  # The host is unreachable
    rescue
      @core.log("Unknown error connecting to #{format_name()}")
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
      @core.log("Disconnected from #{format_name()}")
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
      @readable || @writable || !@incoming_queue.empty?
    end

    # Stop reading from the socket, usually called when the other end of the socket has stopped writing. This shuts down
    # the reading end of the socket and marks it to stop monitoring. It also clears the read buffer, as anything still in
    # there is an incomplete packet and may be safely discarded. Optionally also clears the incoming packet queue,
    # although this can be maintained in order to finish processing them later.
    # @param clear [Boolean] If `true` then the read buffer and queue is cleared, otherwise they're kept.
    def close_for_reading(clear = false)
      @readable = false
      @socket.shutdown(Socket::SHUT_RD)
      @read_buffer.clear
      return if !clear
      @incoming_queue.clear
      @incoming_queue.close
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
      close_for_writing()
      sent == 0 ? -1 : sent
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
      sent == 0 ? -1 : sent
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
        break if @read_buffer.size < PACKET_HEADER_SIZE + size
        @incoming_queue.push(@read_buffer.slice!(0, PACKET_HEADER_SIZE + size))
      end

      received
    rescue IO::WaitReadable                # Nothing to read
      0
    rescue EOFError                        # Peer stopped writing
      close_for_reading()
      -1
    rescue Errno::EPIPE, Errno::ECONNRESET # Peer closed socket
      close_for_reading()
      -1
    rescue Errno::ESHUTDOWN, IOError       # We closed the socket
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
      @core.log("Sent packet %#04x with protocol %#04x of size %d to %s" % [opcode, protocol, payload.size, format_name()])
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

    # Serialize and dump a tag. A tag is an extension of the standard ed2k protocol allowing to add more data to packets
    # without breaking backwards compatibility, as unknown tags can simply be ignored by clients, since the tag's length
    # is always known.
    #
    # A tag is a triplet formed by a type, an identifier or "name", and the actual value. Not all types are actually used,
    # such as booleans or "bsobs", whatever those are. Here, the type is derived automatically from the supplied value.
    # The tag name can actually be either an integer or a string. Variable-length values are prefixed with its length
    # (2 bytes for strings, 4 bytes for blobs). The tag name is also prefixed by its length (2 bytes).
    #
    # Lugdunum servers added more compact new-style tags which omit the length field. These can be detected by testing the
    # highest bit of the type, which is normally unused. For short string tags, even the string length can be encoded
    # in the type byte, further reducing the tag size by 4 bytes total. New-style tag names must be integers, not strings.
    # The uint8 and uint16 types are only used with new-style tags. New-style are never really sent by eMule, only for
    # storing in files, but they might be received from the server, mainly from search results, which have many tags.
    #
    # @param name [Integer,String] The tag "name", which identifies the tag. It can be an integer opcode, or a string name.
    # @param value [Integer,Float,String] The payload of the tag, its type depends on the tag (`Integer` for integer tags, etc).
    # @return [String] The resulting serialized tag as a binary string.
    # @raise [StandardError] If the supplied value has incorrect type.
    def write_tag(name, value, new = false)
      # Tag key
      if name.is_a?(Integer)
        key = new ? name.chr : [1, name].pack('S<C') # Length field is always 1
      else
        key = [name.bytesize, name].pack('S<a*')
      end
      switch = new ? 0x80 : 0x00 # Toggle type's highest bit to indicate new-style tag

      # Dump tag triplet (type, key, value)
      case value
      when Integer
        if size <= 0xFF && new
          [TAGTYPE_UINT8 | switch, key, value].pack('Ca*C')
        elsif size <= 0xFFFF && new
          [TAGTYPE_UINT16 | switch, key, value].pack('Ca*S<')
        elsif size <= 0xFFFFFFFF
          [TAGTYPE_UINT32 | switch, key, value].pack('Ca*L<')
        else
          [TAGTYPE_UINT64 | switch, key, value].pack('Ca*Q<')
        end
      when String
        length = value.bytesize
        if value.encoding == Encoding::BINARY
          [TAGTYPE_BLOB | switch, key, length, value].pack('Ca*L<a*')
        elsif length <= 16 && new
          [16 + length | switch, key, value].pack('Ca*a*')
        else
          [TAGTYPE_STRING | switch, key, length, value].pack('Ca*S<a*')
        end
      when Float
        [TAGTYPE_FLOAT32 | switch, key, value].pack('Ca*E')
      else
        raise "Invalid tag value type"
      end
    end

    # Parse a list of tags. This can can variable length, so a readable stream is to be passed instead of a string.
    # Reading from the stream will consume bytes. See {#write_tag} for more info on tags.
    # @note Unknown tag types (bool, bool array, bsob) are consumed but rejected.
    # @param stream [IO] The stream to read from.
    # @return [Hash] A hash mapping tag names to the corresponding values. Tag names can be integers or strings.
    def read_tags(stream)
      count = stream.read(4).unpack1('L<')
      count.times.map{
        # Parse type and name (old-style vs new-style tags)
        type = stream.read(1).unpack1('C')
        if type >> 7 & 1 == 1 # Highest bit set => New-style tag
          type &= 0x7F
          name = stream.read(1).unpack1('C')
        else
          length = stream.read(2).unpack1('S<')
          name = stream.read(length)
          name = name.ord if length == 1
        end

        # Parse value
        case type
        when TAGTYPE_UINT8
          value = stream.read(1).unpack1('C')
        when TAGTYPE_UINT16
          value = stream.read(2).unpack1('S<')
        when TAGTYPE_UINT32
          value = stream.read(4).unpack1('L<')
        when TAGTYPE_UINT64
          value = stream.read(8).unpack1('Q<')
        when TAGTYPE_FLOAT32
          value = stream.read(4).unpack1('E')
        when TAGTYPE_STRING
          size = stream.read(2).unpack1('S<')
          value = stream.read(size).force_encoding('UTF-8')
        when TAGTYPE_BLOB
          size = stream.read(4).unpack1('L<') # Was a uint16 prior to 0.42e
          value = stream.read(size).b
        when TAGTYPE_HASH
          value = stream.read(16).b
        when TAGTYPE_BOOL      # Ignore
          stream.seek(1, IO::SEEK_CUR)
          next
        when TAGTYPE_BOOLARRAY # Ignore
          size = stream.read(2).unpack1('S<')
          stream.seek(size / 8 + 1, IO::SEEK_CUR)
          next
        when TAGTYPE_BSOB      # Ignore
          size = stream.read(1).unpack1('C')
          stream.seek(size, IO::SEEK_CUR)
          next
        when 0x11..0x20
          value = stream.read(type - 16).force_encoding('UTF-8')
        else
          @core.log("Received unsupported tag type %#.2x" % type)
          next
        end

        # Map names to values in a hash
        [name, value]
      }.compact.to_h
    end

  end # Connection

end # ED2K
