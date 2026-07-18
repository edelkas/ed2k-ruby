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

    # The TCP port our client will be listening to for incoming connections from both the servers and other clients.
    # It must be reachable, a.k.a. "open", in the router.
    # @return [Integer]
    attr_reader :tcp_port

    # Store session statistics, mostly about traffic.
    # @return [Hash]
    attr_accessor :stats

    LOG_LEVEL_NONE    = 0         # Placeholder to disable logging altogether
    LOG_LEVEL_FATAL   = 1         # Application-breaking errors
    LOG_LEVEL_ERROR   = 2         # Unrecoverable issues, such as connection errors
    LOG_LEVEL_WARNING = 3         # Recoverable issues, such as corrupt packets
    LOG_LEVEL_NOTICE  = 4         # Relevant messages, usually positive
    LOG_LEVEL_INFO    = 5         # Standard information messages
    LOG_LEVEL_DEBUG   = 6         # Verbose information, such as control packets sent, protocol errors, etc
    LOG_LEVEL_TRACE   = 7         # Extremely verbose information, such as data dumps
    MAX_SOCKET_QUEUE  = 128       # Max connections with unfinished handshakes (referred to as "half-open" in eMule)
    TCP_READ_SIZE     = 64 * 1024 # Maximum data in bytes to read from each TCP socket per non-blocking call
    TCP_WRITE_SIZE    = 64 * 1024 # Maximum data in bytes to write to each TCP socket per non-blocking call
    UDP_READ_SIZE     = 64 * 1024 # Maximum size in bytes of a single received UDP datagram (a whole datagram is read at once)
    THREAD_FREQUENCY  = 0.05      # Minimum time in seconds between loop iterations of the core threads, for CPU throttling
    THREAD_TIMEOUT    = 2         # Maximum time in seconds to wait for a loop iteration to finish when stopping a thread
    TIMEOUT_WAIT      = 0.5       # Maximum time in seconds to wait for sockets to be readable/writable before selecting again
    TIMEOUT_CONNECT   = 5         # Maximum time in seconds to wait for connections to establish

    # @param log_level [Integer] The log level for the default logger, from {LOG_LEVEL_FATAL} to {LOG_LEVEL_TRACE}. If you
    #        have set a custom logger (see {#add_logger}) you may want to disable this by setting it to {LOG_LEVEL_NONE}.
    # @param log_traces [Boolean] If set to `false`, traces (the most verbose logs) won't even be sent to the loggers.
    #        This is done to save resources, since generating them could be quite heavy.
    def initialize(log_level: LOG_LEVEL_DEBUG, log_traces: false)
      @init = false
      @servers = {}
      @clients = {}
      @loggers = []
      @log_level = log_level
      @log_traces = log_traces
      @tcp_socket = nil
      @udp_socket = nil
      @waker_socket = nil # Wakes up socket thread select to send outgoing TCP and UDP packets
      @parse_ready = Queue.new # Wakes up packet thread to parse incoming TCP and UDP packets
      @write_ready = Queue.new # Connections ready to send a new UDP packet, not necessary for TCP (they each have their own queues)
      @tcp_handlers = ::Hash.new { |h, k| h[k] = {} }
      @udp_handlers = ::Hash.new { |h, k| h[k] = {} }
      reload_preferences()
      init_stats()
      init_connections()
      @init = true
      log_debug("Initialized core")
    end

    # Initialize the sockets and start monitoring connections.
    # @param port [Integer] The TCP port to bind to and listen for incoming connections.
    # @return [Boolean] Whether the core was started successfully or not.
    def start(port = DEFAULT_TCP_PORT)
      config(tcp_port: port)
      return unless init_tcp_socket()
      return unless init_udp_socket()
      init_waker()
      start_socket_thread()
      start_packet_thread()
      log_info("Started core")
      true
    rescue => e
      log_error("Unknown error starting core: #{e}")
      @tcp_socket = nil
      false
    end

    # Stop monitoring connections and close sockets.
    # @return [Boolean] Whether the core was stopped succesfully.
    # @todo Add an option to forcefully stop (kill) the core, or perhaps a different method
    def stop
      return false if !stop_socket_thread()
      if @tcp_socket
        log_info("Stopped TCP server on port #{@tcp_socket.local_address.ip_port}")
        @tcp_socket.close()
        @tcp_socket = nil
      end
      if @waker_socket
        @waker_socket.close
        @waker_socket = nil
      end
      if @udp_socket
        log_info("Stopped UDP server on port #{@udp_socket.local_address.ip_port}")
        @udp_socket.close
        @udp_socket = nil
      end
      @connections.each{ |fileno, conn| disconnect(conn) }
      return false if !stop_packet_thread()
      log_info("Stopped core")
      true
    end

    # Establish a connection with a given server or client.
    # @param conn [Connection] The {Server} or {Client} instance.
    # @return [Boolean] Whether the connection could be established.
    def connect(conn)
      wait = TIMEOUT_CONNECT
      freq = 0.25
      while (status = conn.connect).nil? && wait > 0
        sleep(freq)
        wait -= freq
      end
      log_warning("Connection to #{conn.format_name()} timed out") if status.nil?
      return false if !status
      add_connection(conn)
      true
    end

    # Close a connection with a given server or client.
    # @param conn [Connection] The {Server} or {Client} instance.
    def disconnect(conn)
      remove_connection(conn)
      conn.disconnect
    end

    # Read user preferences from disk and fill the missing ones with the default values
    def reload_preferences
      @tcp_port = DEFAULT_TCP_PORT
      @udp_port = DEFAULT_UDP_PORT
      log_info("Loaded preferences")
    end

    # Change some individual configurations. Only non-null parameters will actually be changed.
    # @param tcp_port [Integer] Port our client will be listening to for incoming TCP connections, should be reachable ("open").
    # @param udp_port [Integer] Ditto for new incoming UDP packets.
    # @todo Prevent ports from being changed when connections have already been made. A core restart should probably be required.
    def config(tcp_port: nil, udp_port: nil)
      if tcp_port
        @tcp_port = tcp_port
        log_debug("TCP port was changed to #{@tcp_port}")
      end

      if udp_port
        @udp_port = udp_port
        log_debug("UDP port was changed to #{@udp_port}")
      end
    end

    # Starts the socket thread and begins monitoring network IO.
    # @note This is done automatically by {#initialize}, only do manually if stopped manually or if it crashed.
    # @return [Thread] The socket thread object
    def start_socket_thread
      @thSockRun = true
      return @thSock if @thSock&.alive?
      @thSockFreq = THREAD_FREQUENCY # Deprecated, no longer using a rate-limit approach
      @thSockTick = Time.now
      @thSock = Thread.new{ run_socket_thread() }
      log_debug("Started socket thread: Data transfer enabled. Listening on TCP port #{@tcp_port}.")
    end

    # Starts the packet thread and begins monitoring incoming packets to be parsed
    # @note This is done automatically by {#initialize}, only do manually if stopped manually or if it crashed.
    # @return [Thread] The packet thread object
    def start_packet_thread
      @thPackRun = true
      return @thPack if @thPack&.alive?
      @thPackFreq = THREAD_FREQUENCY # Deprecated, packet thread is now event-based (blocks on the ready queue)
      @thPackTick = Time.now
      @thPack = Thread.new{ run_packet_thread() }
      log_debug("Started packet thread: Monitoring incoming packets.")
    end

    # Attempts to stop the socket thread gracefully and end network monitoring. It will wait until the current loop is
    # finished, which is normally very quick. It does **not** close the sockets afterwards.
    # @note This is done automatically when disconnecting.
    # @see #kill_socket_thread
    # @return [Boolean] `true` if the thread isn't running or was stopped successfully, `false` otherwise.
    def stop_socket_thread
      return true if !@thSock&.alive?
      @thSockRun = false
      wake_socket_thread()
      return false if !@thSock.join(THREAD_TIMEOUT)
      @thSock.kill
      log_debug("Killed socket thread: Stopped data transfer.")
      true
    end

    # Attempts to stop the packet thread gracefully and end packet parsing. It will wait until the current loop is
    # finished, which is normally very quick.
    # @note This is done automatically when disconnecting.
    # @see #kill_packet_thread
    # @return [Boolean] `true` if the thread isn't running or was stopped successfully, `false` otherwise.
    def stop_packet_thread
      return true if !@thPack&.alive?
      @thPackRun = false
      @parse_ready.push(nil) # Unblock the pop so the thread notices the cleared run flag and exits
      return false if !@thPack.join(THREAD_TIMEOUT)
      @thPack.kill
      log_debug("Killed packet thread: Stopped monitoring incoming packets.")
      true
    end

    # Forcefully kill the socket thread and stop network monitoring. It does **not** close the sockets afterwards.
    # @see #stop_socket_thread
    # @return [Boolean] `true` if the thread was killed, `false` if it wasn't running.
    def kill_socket_thread
      return false if !@thSock&.alive?
      @thSockRun = false
      @thSock.kill
      log_debug("Killed socket thread: Stopped data transfer.")
      true
    end

    # Forcefully kill the packet thread and stop packet parsing.
    # @see #stop_packet_thread
    # @return [Boolean] `true` if the thread was killed, `false` if it wasn't running.
    def kill_packet_thread
      return false if !@thPack&.alive?
      @thPackRun = false
      @thPack.kill
      log_debug("Killed packet thread: Stopped monitoring incoming packets.")
      true
    end

    # Add a handler for logging events triggered by the core. You can add multiple handlers.
    # @yieldparam msg [String] The logged message, might contain multiple lines.
    # @yieldparam level [Integer] The level / severity of the message, from {LOG_LEVEL_FATAL} to {LOG_LEVEL_TRACE}.
    # @return [Proc] The resulting handler
    def add_logger(&logger)
      @loggers << logger
    end


    # Add a handler for the server reject packet. It contains no payload and is sent when the server has rejected our
    # last command, usually due to malformed parameters, incorrect protocol being used, or something similar.
    # @see Server#parse_reject
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [String] This will be empty, but is left here for compatibility.
    # @return [Proc] The resulting handler
    def handle_reject(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_REJECT] = handler
    end

    # Add a handler for the server list packet. It contains a server's list of other known servers as (IP, Port) pairs.
    # This packet is only sent as a response to {Server#send_server_list_request}.
    # @see Server#parse_server_list
    # @see Server#send_server_list_request
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [Server::ServerListStruct] Contains the list of servers' IP and port pairs.
    # @return [Proc] The resulting handler
    def handle_server_list(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_SERVERLIST] = handler
    end

    # Add a handler for the server status packet. It contains the server's current user and file count, and is usually
    # received right after logging in.
    # @see Server#parse_server_status
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [Server::ServerStatusStruct] Contains the server's user and file count.
    # @return [Proc] The resulting handler
    def handle_server_status(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_SERVERSTATUS] = handler
    end

    # Add a handler for the server message packet.
    # These are informative notices sent by the server, each packet can contain multiple ones.
    # Some standard ones have special meanings:
    #
    # - `ERROR: ...` -> An error message, usually printed red by eMule.
    # - `WARNING: ...` -> A warning message, usually printed purple by eMule.
    # - `server version xx.xx` -> The version of eserver running, nowadays usually 17.15.
    # - `[emDynIP: StaticHostName.host:Port]` -> Server instructs us to use DNS because their IP is dynamic and thus subject to change
    #   ([read more](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=132&rm=show_topic)).
    # @see Server#parse_server_message
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [Server::ServerMessageStruct] Contains the list of messages.
    # @return [Proc] The resulting handler
    def handle_server_message(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_SERVERMESSAGE] = handler
    end

    # Add a handler for the server ID change packet.
    # Received whenever our session ID changes in the server. This usually only happens when we log into the server, and
    # it contains our assigned ID, but technically it can happen at any time, so it should be carefully monitored. Since
    # Lugdunum 16.44 it also contains flags with server capabilities, as well as additional information about our client.
    # @see Server#parse_id_change
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [Server::IdChangeStruct] Contains our new ID, server flags, etc.
    # @return [Proc] The resulting handler
    def handle_id_change(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_IDCHANGE] = handler
    end

    # Add a handler for the server identification packet. It contains the hash (a sort of GUID to identify the server),
    # the IP address and port to connect to it, and its name and short description. This packet is sent as a response to
    # {Server#send_server_list_request}.
    # @see Server#parse_server_identification
    # @yieldparam server [Server] The server that sent this packet.
    # @yieldparam payload [Server::ServerIdentificationStruct] Contains the server's hash, IP, port, name and description.
    # @return [Proc] The resulting handler
    def handle_server_identification(&handler)
      @tcp_handlers[OP_EDONKEYPROT][OP_SERVERIDENT] = handler
    end

    # Get a known client by address. Only one of the parameters needs to be specified.
    # @param address [Addrinfo] The full address structure of the client.
    # @param ip [String] The IPv4 address of the client.
    # @return [Client,nil] The client object if known, `nil` otherwise.
    def get_client(address: nil, ip: nil)
      @clients[ED2K::pack_ip(ip || address.ip_address)]
    end

    # Get a known server by address. Only one of the parameters needs to be specified.
    # @param address [Addrinfo] The full address structure of the server.
    # @param ip [String] The IPv4 address of the server.
    # @return [Server,nil] The server object if known, `nil` otherwise.
    def get_server(address: nil, ip: nil)
      @servers[ED2K::pack_ip(ip || address.ip_address)]
    end

    # Add a new client to the list of known ones. If we're already connected we can simply supply the socket, otherwise
    # we need to provide both the address and port.
    # @param ip [String] The IPv4 address of the client
    # @param port [Integer] The port the client is listening to
    # @param socket [Socket] The socket if the connection is already established (they connected to us)
    # @return [Client] The newly created client instance.
    # @todo Careful with the distinction between ID and IP.
    def add_client(ip: nil, port: nil, socket: nil)
      key = ED2K::pack_ip(ip || socket.remote_address.ip_address)
      return @clients[key] if @clients.key?(key)
      client = Client.new(id: ip, port: port, socket: socket, core: self)
      log_debug("New known client: #{client.format_name()}")
      @clients[key] = client
    end

    # Add a new server to the list of known ones.
    # @param ip [String] The IPv4 address of the server.
    # @param port [Integer] The port to connect to.
    # @return [Server] The newly created server instance.
    def add_server(ip, port)
      key = ED2K::pack_ip(ip)
      return @servers[key] if @servers.key?(key)
      server = Server.new(ip, port, core: self)
      log_debug("New known server: #{server.format_name()}")
      @servers[key] = server
    end

    # The following methods shouldn't really be called by the user of the gem while designing their client, but they can't
    # be private either because other classes need to use them.

    # @private
    def log_fatal(msg)
      log(msg, LOG_LEVEL_FATAL)
    end

    # @private
    def log_error(msg)
      log(msg, LOG_LEVEL_ERROR)
    end

    # @private
    def log_warning(msg)
      log(msg, LOG_LEVEL_WARNING)
    end

    # @private
    def log_notice(msg)
      log(msg, LOG_LEVEL_NOTICE)
    end

    # @private
    def log_info(msg)
      log(msg, LOG_LEVEL_INFO)
    end

    # @private
    def log_debug(msg)
      log(msg, LOG_LEVEL_DEBUG)
    end

    # @private
    def log_trace(msg)
      return unless @log_traces
      msg = ED2K::serialize(msg) if msg.encoding.to_s == "ASCII-8BIT"
      log(msg, LOG_LEVEL_TRACE)
    end

    # @private
    def run_tcp_handler(protocol, opcode, peer, data)
      @tcp_handlers&.[](protocol)&.[](opcode)&.call(peer, data)
    end

    # @private
    # Run a handler for a packet received over UDP. UDP opcodes overlap TCP ones but mean different things, so UDP
    # handlers live in their own registry, separate from the TCP handlers used by {#run_tcp_handler}.
    def run_udp_handler(protocol, opcode, peer, data)
      @udp_handlers&.[](protocol)&.[](opcode)&.call(peer, data)
    end

    # @private
    # Schedule a connection to have one of its pending incoming packets processed by the packet thread. Called once per
    # received packet, so the number of tokens in the ready queue always matches the number of packets waiting to be
    # processed across all connections. The channel (:tcp or :udp) selects which of the connection's incoming queues the
    # packet thread will pop from and how it will be parsed.
    def schedule_packet(conn, channel = :tcp)
      @parse_ready.push([conn, channel])
    end

    # @private
    # Schedule a connection to have one of its queued outgoing UDP datagrams sent by the socket thread. Called once per
    # queued datagram, so the number of tokens in the send-readiness queue matches the number of datagrams waiting to be
    # sent across all connections. Wakes the socket thread so it adds the UDP socket to the select write set right away.
    def schedule_udp_send(conn)
      @write_ready.push(conn)
      wake_socket_thread()
    end

    # @private
    # Wake up the socket thread by writing to the waker socket, interrupting the select so that newly queued
    # outgoing packets are noticed immediately instead of after the select timeout.
    def wake_socket_thread
      @waker_socket&.send('!', 0)
    rescue IOError, SystemCallError
      # Waker is closed or broken, the socket thread will still notice the work after the select timeout
    end

    private

    # Add a message to the log of this core.
    def log(msg, level = LOG_LEVEL_INFO)
      @loggers.each{ |logger| logger.call(msg, level) }
      return if level > @log_level
      prefix = "\x1B[%dm" % [41, 31, 33, 34, 0, 35, 90][level - 1]
      suffix = "\x1B[0m"
      msg.each_line(chomp: true){ |line|
        puts "%s[%s] %s%s" % [prefix, Time.now.strftime('%F %T.%L'), line, suffix]
      }
    end

    # Socket thread permanently monitors sockets for R/W activity
    def run_socket_thread
      while @thSockRun
        # Block until next socket activity
        to_read  = @connections.values.select(&:ready_for_reading).map(&:socket)
        to_write = @connections.values.select(&:ready_for_writing).map(&:socket)
        to_read.push(@tcp_socket, @waker_socket, @udp_socket)
        to_write.push(@udp_socket) if !@write_ready.empty?
        readable, writable = IO.select(to_read, to_write, [], TIMEOUT_WAIT)

        # Ditch dead sockets
        @connections.each do |fileno, conn|
          disconnect(conn) if !conn.alive?
        end

        # Read from sockets, fixed budget per socket so fast sockets don't starve the bandwidth
        readable.each do |socket|
          # New incoming connection, accept it
          next new_connection(socket.accept) if socket == @tcp_socket

          # Waker signal, drain it (its only purpose was to interrupt the select)
          next drain_waker() if socket == @waker_socket

          # Incoming UDP datagrams on the shared UDP socket, demux and route them by sender
          next receive_udp() if socket == @udp_socket

          # Server or client activity, read data
          connection = @connections[socket.fileno]
          connection.read(TCP_READ_SIZE)
        end if readable&.any?

        # Write to sockets, sending at most one budget's worth to each one, for the same fairness reasons as above
        writable.each do |socket|
          # Pending outgoing UDP datagrams on the shared UDP socket, send them for whichever connections queued them
          next send_udp() if socket == @udp_socket

          # Send pending TCP packets
          connection = @connections[socket.fileno]
          connection.write(TCP_WRITE_SIZE)
        end if writable&.any?
      end
    end

    # Packet thread monitors the ready queue for connections with new received packets to parse and process. Each entry
    # in the ready queue is a scheduling token, a [connection, channel] pair pushed once per received packet (channel is
    # :tcp or :udp), so we process exactly one packet per token. The blocking pop means the thread consumes no resources
    # while idle.
    def run_packet_thread
      while @thPackRun
        token = @parse_ready.pop
        next if token.nil? # Sentinel pushed on shutdown (or spurious), re-check the run flag
        conn, channel = token
        conn.process_one_packet(channel)
      end
    end

    # Initialize the waker socket, a loopback UDP socket connected to itself. Any thread can write to it to interrupt
    # the socket thread's select and have it recompute the select sets right away.
    def init_waker
      @waker_socket = Socket.new(:INET, :DGRAM)
      @waker_socket.bind(Socket.pack_sockaddr_in(0, '127.0.0.1'))
      @waker_socket.connect(@waker_socket.local_address)
    end

    # Discard any pending datagrams from the waker socket so the select doesn't keep triggering for them
    def drain_waker
      loop { @waker_socket.recv_nonblock(16) }
    rescue IO::WaitReadable
    end

    # Initialize TCP control socket. This socket is mainly used to receive incoming connections from other clients,
    # although it's also used by servers to verify if we're reachable after logging in, in which case we'll be
    # assigned a High ID.
    def init_tcp_socket
      @tcp_socket = Socket.new(:INET, :STREAM)
      @tcp_socket.bind(Socket.pack_sockaddr_in(@tcp_port, '0.0.0.0'))
      @tcp_socket.listen(MAX_SOCKET_QUEUE)
      true
    rescue Errno::EADDRINUSE
      log_error("Failed to start core: The TCP port #{@tcp_port} is already in use")
      @tcp_socket = nil
      false
    end

    # Initialize the single UDP socket shared by the whole core. Unlike TCP, where each connection owns a socket, all UDP
    # traffic (to and from every server and client) goes through this one socket bound to our UDP port. It's monitored by
    # the socket thread for both reading (incoming datagrams) and writing (queued outgoing datagrams).
    def init_udp_socket
      @udp_socket = Socket.new(:INET, :DGRAM)
      @udp_socket.bind(Socket.pack_sockaddr_in(@udp_port, '0.0.0.0'))
      true
    rescue Errno::EADDRINUSE
      log_error("Failed to start core: The UDP port #{@udp_port} is already in use")
      @udp_socket = nil
      false
    end

    # Read and route all currently available UDP datagrams. Since datagrams are self-contained there's no reassembly: each
    # one is a complete packet. We demultiplex by sender IP to the corresponding server or client and hand it off to that
    # connection's incoming UDP queue, scheduling it for the packet thread just like a TCP packet. Datagrams from unknown
    # peers are dropped (they can't be attributed to a connection yet).
    def receive_udp
      loop do
        data, addr = @udp_socket.recvfrom_nonblock(UDP_READ_SIZE)
        @stats[:in_data] += data.bytesize
        conn = get_client(ip: addr.ip_address) || get_server(ip: addr.ip_address)
        if conn
          conn.enqueue_incoming_udp(data)
          schedule_packet(conn, :udp)
        else
          log_debug("Received UDP datagram from unknown peer #{addr.ip_address}:#{addr.ip_port}, dropping")
        end
      end
    rescue IO::WaitReadable # No more datagrams to read
    end

    # Send as many queued outgoing UDP datagrams as possible through the shared UDP socket. Each token in the send-readiness
    # queue corresponds to one datagram queued on some connection, so we pop a token, pop that connection's next datagram
    # and send it to the connection's UDP address. If the send buffer is full we requeue the datagram and stop, retrying
    # when the socket reports writable again. Datagrams are best-effort, so send errors just drop the datagram.
    def send_udp
      loop do
        conn = @write_ready.pop(true)
        packet = conn.dequeue_outgoing_udp
        next if !packet || !conn.udp_address # Stale token (queue already drained) or unknown destination
        begin
          @udp_socket.sendmsg_nonblock(packet, 0, conn.udp_address)
          @stats[:out_data] += packet.bytesize
        rescue IO::WaitWritable # Send buffer full, requeue and retry on the next writable event
          conn.requeue_outgoing_udp(packet)
          @write_ready.push(conn)
          break
        rescue SystemCallError => e # e.g. ECONNREFUSED from a prior ICMP port-unreachable; UDP is best-effort, drop it
          log_debug("Failed to send UDP datagram to #{conn.format_name()}: #{e.message}")
        end
      end
    rescue ThreadError # No more pending outgoing UDP datagrams
    end

    # Initialize the structure storing all connections that need to be monitored for either read or write activity.
    # We use a hash keyed on the underlying socket's file descriptor.
    def init_connections
      @connections = {}
    end

    # Add a connection for IO monitoring
    def add_connection(conn)
      @connections[conn.socket.fileno] = conn
      wake_socket_thread()
    end

    # Parse a new incoming connection and retrieve it (if already known) or create it
    def new_connection(socket)
      addr = socket.remote_address
      if host = get_server(address: addr)
        log_debug("Received new incoming connection from known server #{host.format_name()}")
      elsif host = get_client(address: addr)
        log_debug("Received new incoming connection from known client #{host.format_name()}")
      else
        host = add_client(socket: socket)
      end
      host.tcp_setup
      add_connection(host)
    end

    # Stop monitoring a connection and remove the reference to it
    def remove_connection(conn)
      @connections.delete(conn.socket.fileno)
    end

    # Initialize stats for this session
    def init_stats
      @stats = {
        in_data:         0,
        out_data:        0,
        in_packets:      0,
        out_packets:     0,
        in_packets_bad:  0,
        out_packets_bad: 0
      }
    end

  end # Core

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
    end

    # Initialize resources to prepare communication. This includes R/W buffers, packet queues and state variables.
    # Must be called once before exchanging messages with a server/client, usually right before or after establishing
    # a connection.
    def tcp_setup
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

end # ED2K
