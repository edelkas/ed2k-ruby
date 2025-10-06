require 'socket'

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

    SOCKET_READ_SIZE         = 16 * 1024 # Maximum data in bytes to read from each socket in a single non-blocking call
    DEFAULT_THREAD_FREQUENCY = 0.05      # Minimum time in seconds between loop iterations of the core threads, for CPU throttling
    DEFAULT_THREAD_TIMEOUT   = 1         # Maximum time in seconds to wait for a loop iteration to finish when stopping a thread

    def initialize
      @init = false
      reload_preferences()

      # Init socket thread
      init_sockets()
      @control_socket = TCPServer.new(@tcp_port)
      start_socket_thread()
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

    # Forcefully kill the socket thread and stop network monitoring. It does **not** close the sockets afterwards.
    # @see #stop_socket_thread
    # @return [Boolean] `true` if the thread was killed, `false` if it wasn't running.
    def kill_socket_thread
      return false if !@thSock&.alive?
      @thSockRun = false
      @thSock.kill
      true
    end

    private

    # Socket thread permanently monitors sockets for R/W activity
    def run_socket_thread
      while @thSockRun
        # Block until next socket activity
        to_read = [@control_socket, **@sockets]
        to_write = @sockets
        readable, writable = IO.select(to_read, to_write)

        # Read from sockets
        readable.each do |socket|
          # New incoming connection, accept it
          if socket == @control_socket
            add_socket(socket.accept)
            next
          end

          # Server or client activity, read data
          # TODO: We should defer reading and writing to the client objects themselves, who manage their buffers
          #data = socket.read_nonblock(SOCKET_READ_SIZE)

        end

        # Write to sockets
        writable.each do |socket|

        end

        # Prepare next iteration
        current_time = Time.now
        elapsed = current_time - @thSockTick
        @thSockTick = current_time
        sleep(@thSockFreq - elapsed) if elapsed < @thSockFreq
      end
    end

    # Initialize the structure storing all sockets that need to be monitored. They're all monitored for both read and
    # write activity. For now we use a simple array, since that's what IO.select requires, but this may change for
    # something better in the future.
    def init_sockets
      @sockets = []
    end

    # Add a new socket for IO monitoring
    def add_socket(socket)
      @sockets << socket
    end

    # Stop monitoring a socket and remove the reference to it
    def remove_socket(socket)
      @sockets.delete(socket)
    end
  end
end
