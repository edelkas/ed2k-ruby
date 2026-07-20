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
    DEFAULT_DOWN_RATE = 0         # Default maximum download rate in bytes per second (0 = unlimited)
    DEFAULT_UP_RATE   = 0         # Default maximum upload rate in bytes per second (0 = unlimited)

    # @param log_level [Integer] The log level for the default logger, from {LOG_LEVEL_FATAL} to {LOG_LEVEL_TRACE}. If you
    #        have set a custom logger (see {#add_logger}) you may want to disable this by setting it to {LOG_LEVEL_NONE}.
    # @param log_traces [Boolean] If set to `false`, traces (the most verbose logs) won't even be sent to the loggers.
    #        This is done to save resources, since generating them could be quite heavy.
    # @param down_rate [Integer] Maximum download rate in bytes per second, aggregated over every peer. `0` is
    #        unlimited, and costs nothing to check. See {#config} to change it on a running core.
    # @param up_rate [Integer] Ditto for the upload rate.
    def initialize(log_level: LOG_LEVEL_DEBUG, log_traces: false, down_rate: DEFAULT_DOWN_RATE, up_rate: DEFAULT_UP_RATE)
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
      @down_bucket = TokenBucket.new(down_rate) # Meters everything we receive, across all peers
      @up_bucket   = TokenBucket.new(up_rate)   # Ditto for everything we send
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
        log_info("Stopped TCP server on port #{socket_port(@tcp_socket) || @tcp_port}")
        close_quietly(@tcp_socket)
        @tcp_socket = nil
      end
      if @waker_socket
        close_quietly(@waker_socket)
        @waker_socket = nil
      end
      if @udp_socket
        log_info("Stopped UDP server on port #{socket_port(@udp_socket) || @udp_port}")
        close_quietly(@udp_socket)
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
    # @param down_rate [Integer] Maximum download rate in bytes per second, aggregated over every peer, `0` for unlimited.
    #        Takes effect immediately, without a burst at the previous allowance first.
    # @param up_rate [Integer] Ditto for the upload rate.
    # @todo Prevent ports from being changed when connections have already been made. A core restart should probably be required.
    def config(tcp_port: nil, udp_port: nil, down_rate: nil, up_rate: nil)
      if tcp_port
        @tcp_port = tcp_port
        log_debug("TCP port was changed to #{@tcp_port}")
      end

      if udp_port
        @udp_port = udp_port
        log_debug("UDP port was changed to #{@udp_port}")
      end

      if down_rate
        @down_bucket.rate = down_rate
        log_debug("Download rate limit was changed to #{format_rate(@down_bucket.rate)}")
        wake_socket_thread()
      end

      if up_rate
        @up_bucket.rate = up_rate
        log_debug("Upload rate limit was changed to #{format_rate(@up_bucket.rate)}")
        wake_socket_thread()
      end
    end

    # The maximum download rate currently enforced, in bytes per second, or `0` if unlimited.
    # @return [Integer]
    def down_rate
      @down_bucket.rate
    end

    # The maximum upload rate currently enforced, in bytes per second, or `0` if unlimited.
    # @return [Integer]
    def up_rate
      @up_bucket.rate
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

    # Get a known client by address. Only one of the parameters needs to be specified. Clients are keyed by IP alone,
    # so a single host cannot take up more than one client slot by connecting from several ports.
    # @param address [Addrinfo] The full address structure of the client.
    # @param ip [String] The IPv4 address of the client.
    # @return [Client,nil] The client object if known, `nil` otherwise.
    def get_client(address: nil, ip: nil)
      @clients[ip || address.ip_address]
    end

    # Get a known server by address. Only one of `address` and `ip` needs to be specified. Servers are keyed by both IP
    # and port, since several servers may share a single IP address, so `port` should be given whenever it's known to
    # get an exact match. Note that the port is never inferred from `address`, because the addresses we have at hand
    # (the remote end of an incoming connection, or the sender of a UDP datagram) carry the port the server happens to
    # be sending _from_, not the TCP port it's listening on, which is the one used in the key. When no port is supplied
    # the lookup falls back to matching the IP alone, and thus returns the first server found at that address.
    # When no port is given and several servers do share the IP, `prefer` can be supplied to break the tie: it's a
    # callable receiving each candidate and returning whether it's a likely match (e.g. whether it's awaiting an answer
    # from us). The first candidate is returned if the preference doesn't single one out.
    # @param address [Addrinfo] The full address structure of the server (only its IP is used).
    # @param ip [String] The IPv4 address of the server.
    # @param port [Integer] The TCP port the server is listening on.
    # @param prefer [#call] Predicate used to break ties between servers sharing the IP.
    # @return [Server,nil] The server object if known, `nil` otherwise.
    def get_server(address: nil, ip: nil, port: nil, prefer: nil)
      ip ||= address.ip_address
      return @servers[server_key(ip, port)] if port
      resolve_server(ip, prefer).first
    end

    # Add a new client to the list of known ones. If we're already connected we can simply supply the socket, otherwise
    # we need to provide both the address and port.
    # @param ip [String] The IPv4 address of the client
    # @param port [Integer] The port the client is listening to
    # @param socket [Socket] The socket if the connection is already established (they connected to us)
    # @return [Client] The newly created client instance.
    # @todo Careful with the distinction between ID and IP.
    def add_client(ip: nil, port: nil, socket: nil)
      key = ip || socket.remote_address.ip_address
      return @clients[key] if @clients.key?(key)
      client = Client.new(id: ip, port: port, socket: socket, core: self)
      log_debug("New known client: #{client.format_name()}")
      @clients[key] = client
    end

    # Add a new server to the list of known ones. Servers are keyed by both IP and port, so several servers sharing a
    # single IP address can be known at once, which does happen in practice.
    # @param ip [String] The IPv4 address of the server.
    # @param port [Integer] The port to connect to.
    # @return [Server] The newly created server instance.
    def add_server(ip, port)
      key = server_key(ip, port)
      return @servers[key] if @servers.key?(key)
      shared = servers_at(ip)
      if !shared.empty?
        log_debug("New server at an already known IP, %s now hosts %d servers (%s)" % [
          ip, shared.size + 1, (shared.map{ |srv| srv.tcp_address.ip_port } << port).join(', ')
        ])
      end
      server = Server.new(ip, port, core: self)
      log_debug("New known server: #{server.format_name()}")
      @servers[key] = server
    end

    # The following methods shouldn't really be called by the user of the gem while designing their client, but they can't
    # be private either because other classes need to use them.

    # Log methods take either a ready-made message or a block returning one. Prefer the block form wherever the call
    # sits on a hot path, so that nothing is built when the level discards it (see {#log}).

    # @private
    def log_fatal(msg = nil, &block)
      log(msg, LOG_LEVEL_FATAL, &block)
    end

    # @private
    def log_error(msg = nil, &block)
      log(msg, LOG_LEVEL_ERROR, &block)
    end

    # @private
    def log_warning(msg = nil, &block)
      log(msg, LOG_LEVEL_WARNING, &block)
    end

    # @private
    def log_notice(msg = nil, &block)
      log(msg, LOG_LEVEL_NOTICE, &block)
    end

    # @private
    def log_info(msg = nil, &block)
      log(msg, LOG_LEVEL_INFO, &block)
    end

    # @private
    def log_debug(msg = nil, &block)
      log(msg, LOG_LEVEL_DEBUG, &block)
    end

    # @private
    def log_trace(msg = nil)
      return unless @log_traces
      msg = yield if block_given?
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
    # Schedule a connection to have some of its pending incoming packets processed by the packet thread. Each token
    # carries how many packets it accounts for, so the counts across the ready queue always add up to the number of
    # packets waiting to be processed across all connections. The channel (:tcp or :udp) selects which of the connection's
    # incoming queues the packet thread will pop from and how it will be parsed.
    def schedule_packet(conn, channel = :tcp, count = 1)
      return if count <= 0
      @parse_ready.push([conn, channel, count])
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

    # Add a message to the log of this core. The message may be supplied as a block instead of a string, in which case
    # it's only built when something is actually going to consume it. This matters on the hot paths.
    def log(msg = nil, level = LOG_LEVEL_INFO)
      return if block_given? && level > @log_level && @loggers.empty?
      msg = yield if block_given?
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

        # When a rate limit has run out of allowance we stop monitoring the peer sockets altogether until it recovers.
        # Leaving them in the select set instead would busy-loop the thread: select is level triggered, so it would keep
        # reporting them as ready while we decline to transfer anything. Dropping them and sleeping for exactly as long
        # as the allowance needs to recover is both idle and prompt, which is what keeps the achieved rate at the limit
        # rather than below it.
        read_wait  = @down_bucket.wait_time
        write_wait = @up_bucket.wait_time
        to_read.clear  if read_wait > 0
        to_write.clear if write_wait > 0

        to_read.push(@tcp_socket, @waker_socket, @udp_socket)
        to_write.push(@udp_socket) if !@write_ready.empty?

        timeout = TIMEOUT_WAIT
        timeout = read_wait  if read_wait  > 0 && read_wait  < timeout
        timeout = write_wait if write_wait > 0 && write_wait < timeout
        readable, writable = IO.select(to_read, to_write, [], timeout)

        # Ditch dead sockets
        @connections.each do |fileno, conn|
          disconnect(conn) if !conn.alive?
        end

        # Read from sockets, fixed budget per socket so fast sockets don't starve the bandwidth
        readable.each do |socket|
          # New incoming connection, accept it
          next new_connection(socket.accept.first) if socket == @tcp_socket

          # Waker signal, drain it (its only purpose was to interrupt the select)
          next drain_waker() if socket == @waker_socket

          # Incoming UDP datagrams on the shared UDP socket, demux and route them by sender
          next receive_udp() if socket == @udp_socket

          # Server or client activity, read as much as both the per socket budget and the rate limit allow. Peers are
          # served in turn until the allowance runs out, so whatever is left of it always goes to someone who can use
          # it, and the limit is reached as long as the peers can collectively supply it.
          connection = @connections[socket.fileno]
          grant = @down_bucket.take(TCP_READ_SIZE)
          next if grant == 0
          read = connection.read(grant)
          @down_bucket.refund(grant - [read, 0].max) # The peer may have had less to give than we allowed for
        end if readable&.any?

        # Write to sockets, sending at most one budget's worth to each one, for the same fairness reasons as above
        writable.each do |socket|
          # Pending outgoing UDP datagrams on the shared UDP socket, send them for whichever connections queued them
          next send_udp() if socket == @udp_socket

          # Send pending TCP packets, metered the same way as reads
          connection = @connections[socket.fileno]
          grant = @up_bucket.take(TCP_WRITE_SIZE)
          next if grant == 0
          written = connection.write(grant)
          @up_bucket.refund(grant - [written, 0].max) # We may have had less to send than we allowed for
        end if writable&.any?
      end
    end

    # Packet thread monitors the ready queue for connections with new received packets to parse and process. Each entry
    # in the ready queue is a scheduling token, a [connection, channel, count] triple (channel is :tcp or :udp), so we
    # process exactly as many packets as the token accounts for. The blocking pop means the thread consumes no resources
    # while idle.
    def run_packet_thread
      while @thPackRun
        token = @parse_ready.pop
        next if token.nil? # Sentinel pushed on shutdown (or spurious), re-check the run flag
        conn, channel, count = token
        count.times{ conn.process_one_packet(channel) }
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
    rescue SystemCallError => e
      log_error("Failed to start core: #{bind_error(e, 'TCP', @tcp_port)}")
      close_quietly(@tcp_socket)
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
    rescue SystemCallError => e
      log_error("Failed to start core: #{bind_error(e, 'UDP', @udp_port)}")
      close_quietly(@udp_socket)
      @udp_socket = nil
      false
    end

    # Explain why binding a port failed, in terms of what can be done about it. Besides the port simply being taken, the
    # case worth naming is one the system refuses outright: Windows reserves whole blocks of ports for Hyper-V and WinNAT
    # (`netsh interface ipv4 show excludedportrange`), and binding one of those is denied rather than reported as busy.
    # Those reservations are per protocol, so a port that binds fine for TCP may still be refused for UDP, and viceversa.
    # @param error [SystemCallError] The error the bind failed with.
    # @param protocol [String] The protocol being bound, for the message.
    # @param port [Integer] The port we tried to bind.
    # @return [String] A description of the failure.
    def bind_error(error, protocol, port)
      case error
      when Errno::EADDRINUSE    then "The #{protocol} port #{port} is already in use"
      when Errno::EACCES        then "The #{protocol} port #{port} was refused by the system, it may be reserved"
      when Errno::EADDRNOTAVAIL then "The #{protocol} port #{port} is not available on this machine"
      else "Could not bind the #{protocol} port #{port}: #{error.message}"
      end
    end

    # Close a socket, ignoring any complaint about the state it's in. Used on paths whose whole purpose is to get rid of
    # the socket, where a failure to close it tells us nothing we can act on.
    # @param socket [Socket,nil] The socket to close, if there is one.
    def close_quietly(socket)
      socket&.close
    rescue SystemCallError, IOError
    end

    # The port a socket is actually bound to, or `nil` if it isn't bound or is already closed.
    # @param socket [Socket] The socket to inspect.
    # @return [Integer,nil] The bound port, or `nil` if it can't be determined.
    def socket_port(socket)
      socket.local_address.ip_port
    rescue SocketError, SystemCallError, IOError
      nil
    end

    # Read and route all currently available UDP datagrams. Since datagrams are self-contained there's no reassembly: each
    # one is a complete packet. We demultiplex by sender IP to the corresponding server or client and hand it off to that
    # connection's incoming UDP queue, scheduling it for the packet thread just like a TCP packet. Datagrams from unknown
    # peers are dropped (they can't be attributed to a connection yet).
    def receive_udp
      loop do
        begin
          data, addr = @udp_socket.recvfrom_nonblock(UDP_READ_SIZE)
        rescue Errno::ECONNRESET, Errno::ENETRESET => e
          # A datagram we sent earlier bounced back as an ICMP unreachable, which the OS reports here rather than on the
          # send itself. The socket is still perfectly usable, so just note it and carry on draining.
          log_debug("Previous UDP datagram could not be delivered: #{e.message}")
          next
        end
        @stats[:in_data] += data.bytesize
        @down_bucket.deduct(data.bytesize)
        conn = get_client(ip: addr.ip_address)
        if !conn
          conn, ambiguous = resolve_server(addr.ip_address, ->(srv){ srv.pending_udp? })
          # Unlike an incoming TCP connection we don't drop the datagram, since for many UDP replies (source requests,
          # global searches...) the exact server it came from doesn't really matter. It does for others though (status
          # or description requests), hence the warning.
          log_warning("Received UDP datagram from #{addr.ip_address}:#{addr.ip_port}, but several known servers share "\
                      "that IP and none is uniquely awaiting an answer, attributing it to #{conn.format_name()}") if ambiguous
        end
        if conn
          conn.udp_answered
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
          @up_bucket.deduct(packet.bytesize)
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

    # Render a transfer rate in human readable form.
    # @param rate [Integer] The rate in bytes per second, `0` meaning unlimited.
    # @return [String] The formatted rate.
    def format_rate(rate)
      return 'unlimited' if rate == 0
      units = ['B/s', 'KB/s', 'MB/s', 'GB/s']
      index = 0
      value = rate.to_f
      while value >= 1024 && index < units.size - 1
        value /= 1024
        index += 1
      end
      "%.4g %s" % [value, units[index]]
    end

    # Build the key under which a server is stored in the list of known ones, which combines both its IP address and the
    # TCP port it listens on, as opposed to clients, which are keyed by IP address alone.
    # @param ip [String] The IPv4 address of the server.
    # @param port [Integer] The TCP port the server is listening on.
    # @return [String] The key, in `ip:port` form.
    def server_key(ip, port)
      "#{ip}:#{port}"
    end

    # All known servers listening on a given IP address. Normally there's at most one, but a single host may run
    # several servers on different ports, which does happen in practice.
    # @param ip [String] The IPv4 address to look up.
    # @return [Array<Server>] The servers at that address, possibly empty.
    def servers_at(ip)
      @servers.each_value.select{ |server| server.tcp_address.ip_address == ip }
    end

    # Figure out which server a message came from, given only the IP address it was sent from. Incoming messages don't
    # carry the port the server listens on (see {#get_server}), so when several servers share an IP we can't tell them
    # apart by address alone and have to fall back on a heuristic: servers only really contact us to answer something we
    # asked, so the caller supplies a predicate marking which candidates are awaiting an answer. If exactly one is, it's
    # our server. Otherwise the tie is unresolved and the caller decides what to do about it.
    # @param ip [String] The IPv4 address the message came from.
    # @param prefer [#call,nil] Predicate telling whether a candidate is awaiting an answer from us.
    # @return [Array(Server,Boolean)] The best candidate (`nil` if the IP is unknown), and whether it stayed ambiguous.
    def resolve_server(ip, prefer = nil)
      candidates = servers_at(ip)
      return [candidates.first, false] if candidates.size <= 1
      preferred = prefer ? candidates.select{ |server| prefer.call(server) } : []
      return [preferred.first, false] if preferred.size == 1
      [candidates.first, true]
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

    # Parse a new incoming connection and retrieve it (if already known) or create it. Servers only ever connect to us to
    # answer a login request, so that's what we use to tell apart several servers sharing the IP the connection came
    # from. If that isn't enough we drop the connection, since attributing it to the wrong server (or, worse, taking it
    # for a brand new client) would be more harmful than losing it.
    def new_connection(socket)
      addr = socket.remote_address
      server, ambiguous = resolve_server(addr.ip_address, ->(srv){ srv.pending_login })
      if ambiguous
        log_error("Received new incoming connection from #{addr.ip_address}:#{addr.ip_port}, but several known servers "\
                  "share that IP and the login state doesn't tell them apart, dropping it")
        return socket.close
      end

      if host = server
        log_debug("Received new incoming connection from known server #{host.format_name()}")
      elsif host = get_client(address: addr)
        log_debug("Received new incoming connection from known client #{host.format_name()}")
      else
        host = add_client(socket: socket)
      end
      host.tcp_setup(socket)
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

end # ED2K
