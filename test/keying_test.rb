# How known servers and clients are keyed and looked up ({ED2K::Core#add_server}, {ED2K::Core#get_server}
# and their client counterparts), plus the accepting of incoming connections.

require_relative 'helper.rb'

with_core do |core|
  section 'Servers are keyed by IP and port'
  s1 = core.add_server('127.0.0.1', 4661)
  s2 = core.add_server('127.0.0.1', 4665)
  servers = core.instance_variable_get(:@servers)
  check(!s1.equal?(s2), "two servers on one IP but different ports are distinct objects")
  check(servers.size == 2, "both are stored (got #{servers.size})")
  check(servers.keys.sort == ['127.0.0.1:4661', '127.0.0.1:4665'], "keys are 'ip:port' (got #{servers.keys.sort.inspect})")

  check(core.add_server('127.0.0.1', 4661).equal?(s1), "re-adding the same ip:port returns the existing server")
  check(servers.size == 2, "re-adding creates no duplicate")

  section 'Looking servers up'
  check(core.get_server(ip: '127.0.0.1', port: 4665).equal?(s2), "an exact ip+port match resolves")
  check(core.get_server(ip: '127.0.0.1', port: 4661).equal?(s1), "so does the other one")
  check(core.get_server(ip: '127.0.0.1', port: 9999).nil?, "an unknown port resolves to nothing")
  check(core.get_server(ip: '10.1.2.3').nil?, "an unknown IP resolves to nothing")
  check([s1, s2].include?(core.get_server(ip: '127.0.0.1')), "without a port it falls back to an IP match")

  # The port of an incoming address is the one the peer is sending *from*, not the one it listens
  # on, so it must never be folded into the lookup key.
  ephemeral = Addrinfo.new(Socket.pack_sockaddr_in(54321, '127.0.0.1'))
  check(!core.get_server(address: ephemeral).nil?, "an address' port is ignored, matching by IP alone")

  # '127.0.0.1:' must not prefix-match '127.0.0.10:'
  core.add_server('127.0.0.10', 4661)
  found = core.get_server(ip: '127.0.0.10', port: 4661)
  check(found && found.tcp_address.ip_address == '127.0.0.10', "similar IPs don't collide")

  section 'Clients are keyed by IP alone'
  # Deliberately port-blind, so one host can't take up several client slots by using several ports.
  c1 = core.add_client(ip: '192.168.1.5', port: 1111)
  c2 = core.add_client(ip: '192.168.1.5', port: 2222)
  check(c1.equal?(c2), "the same IP on a different port is the same client")
  check(core.instance_variable_get(:@clients).keys == ['192.168.1.5'], "keys are plain IP strings")
  check(core.get_client(ip: '192.168.1.5').equal?(c1), "lookup by IP resolves")
  check(core.get_client(address: Addrinfo.new(Socket.pack_sockaddr_in(9999, '192.168.1.5'))).equal?(c1),
        "lookup by address resolves regardless of its port")
  check(core.get_client(ip: '8.8.8.8').nil?, "an unknown IP resolves to nothing")
end

section 'Accepting an incoming connection'
# Socket#accept returns a [socket, addrinfo] pair, unlike TCPServer#accept which returns the bare
# socket. Unpacking it wrongly used to kill the socket thread on every inbound connection.
with_core do |core|
  peer = TCPSocket.new('127.0.0.1', core.tcp_port)
  connected = wait_for{ !core.instance_variable_get(:@connections).empty? }

  check(core.instance_variable_get(:@thSock).alive?, "the socket thread survives an inbound connection")
  check(connected, "the connection is registered")

  inbound = core.instance_variable_get(:@connections).values.first
  check(inbound && inbound.socket.remote_address.ip_address == '127.0.0.1',
        "what's registered is a socket-backed connection, not the accept pair")
  check(core.get_client(ip: '127.0.0.1').equal?(inbound), "the peer is remembered as a known client")

  # And the connection actually carries traffic
  seen = Queue.new
  inbound.define_singleton_method(:parse_edonkey_tcp_packet){ |opcode, payload| seen.push([opcode, payload.dup]); payload }
  peer.write(tcp_packet(0x01, 'inbound-hello'))
  peer.flush
  check(pop_within(seen) == [0x01, 'inbound-hello'], "a packet sent over it is received and parsed")

  peer.close
end

report
