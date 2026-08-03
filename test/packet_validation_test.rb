# Packet-header validation guards: Connection#validate_tcp_packet_header (TCP) and Connection#validate_udp_packet (UDP).
#
# TCP is a byte stream, so a single mis-framed packet (a bogus length, or a protocol byte that isn't ed2k) would
# desync every packet after it. The TCP guard therefore treats a bad header as unrecoverable and drops the whole
# connection via schedule_disconnect: both ends are closed, which lets the packet thread still drain whatever valid
# packets already made it into the queue, after which the socket thread's reaper tears the connection down. A bad
# header must never be enqueued, and a read that yields no valid packet must not wake the packet thread at all.
#
# UDP is datagram-framed, so one bad datagram can't desync the next. The UDP guard just drops the offending datagram
# (Core#receive_udp returns before enqueuing or scheduling anything) and keeps the connection.
#
# The set of acceptable protocols differs by peer type and channel (the SUPPORTED_*_PROTOCOLS constants on Server and
# Client), mirroring eMule, so the same protocol byte can be valid for one peer and a framing error for another.
#
# The TCP sections drive read() and the validators directly against a core whose threads were never started, so nothing
# races us reading the sockets or draining the ready queue. The end-to-end UDP consequence (dropping without waking the
# packet thread) lives in Core#receive_udp and needs a running core with the UDP socket wired in, so it's gated on
# udp_enabled? like the other UDP tests and lights up on its own once UDP is restored.

require_relative 'helper.rb'

ERROR   = ED2K::Core::LOG_LEVEL_ERROR
WARNING = ED2K::Core::LOG_LEVEL_WARNING
DEBUG   = ED2K::Core::LOG_LEVEL_DEBUG

core = ED2K::Core.new(default_logger: false, log_level: DEBUG)
logs = []
core.add_logger{ |msg, level| logs << [level, msg] }
ready   = core.instance_variable_get(:@parse_ready) # inspected to tell whether the packet thread would be woken
sockets = []

# Build a peer of the given class with a live, connected loopback socket, ready to be fed raw bytes. Returns the
# connection and the remote end of the socket, which the test writes into to play the wire.
def wired(core, sockets, klass)
  listener = TCPServer.new('127.0.0.1', 0)
  ours     = TCPSocket.new('127.0.0.1', listener.addr[1])
  remote   = listener.accept
  sockets.push(listener, ours, remote)
  conn = klass == ED2K::Server ? ED2K::Server.new('127.0.0.1', listener.addr[1], core: core)
                               : ED2K::Client.new(socket: ours, core: core)
  conn.tcp_setup(ours)
  [conn, remote]
end

# Write raw bytes to a connection's socket and run exactly one read pass over them.
def deliver(conn, remote, bytes, timeout: 2)
  remote.write(bytes)
  IO.select([conn.instance_variable_get(:@socket)], nil, nil, timeout) # block until the bytes land
  conn.read(ED2K::Core::TCP_READ_SIZE)
end

# A connection is "dropped" once both ends have been closed, which is exactly what schedule_disconnect does.
def dropped?(conn)
  conn.instance_variable_get(:@readable) == false && conn.instance_variable_get(:@writable) == false
end

def incoming(conn)
  conn.instance_variable_get(:@tcp_incoming_queue)
end

def try_pop(queue)
  queue.pop(true)
rescue ThreadError
  nil
end

section 'A well-formed TCP packet clears the guard and is enqueued'
conn, remote = wired(core, sockets, ED2K::Server)
before = ready.size
deliver(conn, remote, tcp_packet(0x01, 'hi'))
check(incoming(conn).size == 1, "the packet is enqueued for the packet thread")
check(!dropped?(conn), "the connection stays open")
check(ready.size == before + 1, "the packet thread is woken exactly once")
check(try_pop(ready) == [conn, :tcp, 1], "the scheduling token names the connection, channel and count")

section 'An unsupported protocol byte is a framing error and drops the connection'
conn, remote = wired(core, sockets, ED2K::Server)
mark = logs.size
before = ready.size
bad = [0x99, 2, 0x01].pack('CL<C') + 'x' # 0x99 is not an ed2k protocol
deliver(conn, remote, bad)
check(dropped?(conn), "both ends of the connection are closed")
check(incoming(conn).empty?, "nothing is handed to the packet thread")
check(ready.size == before, "the packet thread is not woken")
check(logs_at(logs[mark..], ERROR).count{ |m| m.include?('framing error') && m.include?('invalid protocol') } == 1,
      "a framing error is logged at error level for a server")

section 'An oversized packet is a framing error, but a large-yet-legal one only waits for more data'
conn, remote = wired(core, sockets, ED2K::Server)
mark = logs.size
huge = [ED2K::OP_EDONKEYPROT, ED2K::MAX_PACKET_SIZE + 2, 0x01].pack('CL<C') # claims a payload past the 1 MB cap
deliver(conn, remote, huge)
check(dropped?(conn), "a payload past the size cap drops the connection")
check(logs_at(logs[mark..], ERROR).any?{ |m| m.include?('framing error') && m.include?('size too large') },
      "the oversize is logged as a framing error")

conn, remote = wired(core, sockets, ED2K::Server)
before = ready.size
big = [ED2K::OP_EDONKEYPROT, 50_000, 0x01].pack('CL<C') # a ~50 KB packet, under the cap, only the header so far
deliver(conn, remote, big)
check(!dropped?(conn), "a legal size under the cap is not a framing error")
check(incoming(conn).empty? && ready.size == before, "the incomplete packet just waits, unenqueued and unscheduled")

section 'Valid packets before a bad header still get through; framing stops at the break'
conn, remote = wired(core, sockets, ED2K::Server)
before = ready.size
good = tcp_packet(0x01, 'ok')
junk = [0x99, 2, 0x01].pack('CL<C') + 'x'
never = tcp_packet(0x01, 'never')
deliver(conn, remote, good + junk + never)
check(incoming(conn).size == 1, "only the packet before the bad header is enqueued")
check(try_pop(incoming(conn)) == good, "and it is delivered intact")
check(ready.size == before + 1 && try_pop(ready) == [conn, :tcp, 1],
      "the packet thread is woken, but only for the one valid packet")
check(dropped?(conn), "the connection is still dropped because of the bad header")

section 'The TCP allow-list is per peer type'
# eMule protocol (0xC5) is a valid TCP protocol for a client but a framing error for a server.
srv, srv_remote = wired(core, sockets, ED2K::Server)
deliver(srv, srv_remote, tcp_packet(0x01, 'x', ED2K::OP_EMULEPROT))
check(dropped?(srv), "a server rejects an eMule-protocol packet")

cli, cli_remote = wired(core, sockets, ED2K::Client)
deliver(cli, cli_remote, tcp_packet(0x01, 'x', ED2K::OP_EMULEPROT))
check(!dropped?(cli) && incoming(cli).size == 1, "a client accepts the very same packet")

# A genuinely unknown protocol is rejected by the client too, and a client's framing errors log at warning, not error.
mark = logs.size
deliver(cli, cli_remote, tcp_packet(0x01, 'x', 0x00))
check(dropped?(cli), "a client still drops an unknown protocol")
check(logs_at(logs[mark..], WARNING).any?{ |m| m.include?('framing error') } &&
      logs_at(logs[mark..], ERROR).none?{ |m| m.include?('framing error') },
      "a client logs the framing error at warning level, not error")

section 'A well-formed datagram clears the UDP guard'
srv = ED2K::Server.new('127.0.0.1', 4661, core: core)
check(srv.validate_udp_packet(udp_packet(ED2K::OP_GLOBSERVSTATREQ, 'hi')) == true,
      "a supported-protocol datagram of sufficient length is accepted")

section 'A too-short datagram is dropped by the UDP guard'
check(srv.validate_udp_packet(''.b) == false, "an empty datagram is rejected")
mark = logs.size
check(srv.validate_udp_packet("\xE3".b) == false, "a one-byte datagram (no room for protocol + opcode) is rejected")
check(logs_at(logs[mark..], DEBUG).any?{ |m| m.include?('too short') }, "the drop is logged as too short")

section 'An unsupported-protocol datagram is dropped by the UDP guard'
mark = logs.size
check(srv.validate_udp_packet(udp_packet(0x00, 'hi', 0x00)) == false, "an unknown protocol is rejected")
check(logs_at(logs[mark..], DEBUG).any?{ |m| m.include?('unsupported protocol') }, "the drop is logged")

section 'The UDP allow-list is per peer type'
cli = ED2K::Client.new(socket: nil, core: core)
# eDonkey UDP (0xE3) is valid for a server but not a client; eMule UDP (0xC5) is the reverse.
check(srv.validate_udp_packet(udp_packet(0x00, '', ED2K::OP_EDONKEYPROT)) == true,  "a server accepts an eDonkey datagram")
check(cli.validate_udp_packet(udp_packet(0x00, '', ED2K::OP_EDONKEYPROT)) == false, "a client rejects the same eDonkey datagram")
check(cli.validate_udp_packet(udp_packet(0x00, '', ED2K::OP_EMULEPROT))  == true,  "a client accepts an eMule datagram")
check(srv.validate_udp_packet(udp_packet(0x00, '', ED2K::OP_EMULEPROT))  == false, "a server rejects the same eMule datagram")

sockets.each{ |s| s.close rescue nil }

# The dropping-and-not-waking consequence lives in Core#receive_udp, which needs the UDP socket wired into a running
# core. That path is dormant while UDP is disabled, so this only runs (and only can run) once UDP is back.
if udp_enabled?
  section 'A garbage datagram is dropped by the core without ever reaching the packet thread'
  with_core do |core2, logs2|
    server = core2.add_server('127.0.0.1', 4661)
    seen = Queue.new
    server.define_singleton_method(:parse_edonkey_udp_packet){ |op, payload| seen.push([op, payload.dup]); payload }

    sender = UDPSocket.new
    dest = Socket.pack_sockaddr_in(core2.instance_variable_get(:@udp_port), '127.0.0.1')

    sender.send(udp_packet(0x00, 'x', 0x00), 0, dest) # unsupported protocol
    sender.send("\x00".b, 0, dest)                    # too short
    check(pop_within(seen, timeout: 0.5).nil?, "neither invalid datagram reaches the parser")

    sender.send(udp_packet(ED2K::OP_GLOBSERVSTATREQ, 'ok'), 0, dest) # a valid one, to prove the path still works
    got = pop_within(seen)
    check(got && got[1] == 'ok', "a valid datagram still gets through afterwards")
    sender.close
  end
end

report
