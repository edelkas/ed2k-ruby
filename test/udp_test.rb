# The shared UDP socket: sending queued datagrams and routing received ones.
#
# Unlike TCP, where every connection owns a socket, all UDP traffic goes through a single socket
# bound to the core's UDP port, so datagrams have to be demultiplexed by sender on the way in and
# addressed per connection on the way out.

require_relative 'helper.rb'

section 'A peer\'s UDP address is derived from its TCP port'
with_core do |core|
  server = core.add_server('127.0.0.1', 5000)
  check(server.udp_port == 5004, "the UDP port is the TCP port plus four (got #{server.udp_port.inspect})")
  check(server.udp_address && server.udp_address.ip_port == 5004 && server.udp_address.ip_address == '127.0.0.1',
        "the UDP address is built from it (got #{server.udp_address&.ip_port.inspect})")
end

section 'Receiving datagrams'
with_core do |core|
  server = core.add_server('127.0.0.1', 5000)
  parsed = Queue.new
  server.define_singleton_method(:parse_edonkey_udp_packet){ |op, pl| parsed.push([:edonkey, op, pl.dup]); pl }
  server.define_singleton_method(:parse_emule_udp_packet){ |op, pl| parsed.push([:emule, op, pl.dup]); pl }

  sender = UDPSocket.new
  destination = Socket.pack_sockaddr_in(core.instance_variable_get(:@udp_port), '127.0.0.1')
  sender.send(udp_packet(0x96, 'hello', ED2K::OP_EDONKEYPROT), 0, destination)
  sender.send(udp_packet(0x42, 'world', ED2K::OP_EMULEPROT), 0, destination)

  # Datagram order isn't guaranteed, so compare as a set
  got = [pop_within(parsed), pop_within(parsed)]
  check(got.include?([:edonkey, 0x96, 'hello']), "an edonkey datagram reaches the edonkey parser")
  check(got.include?([:emule, 0x42, 'world']), "an emule datagram reaches the emule parser")
  check(core.stats[:in_packets] == 2, "both are counted (got #{core.stats[:in_packets]})")
  check(core.stats[:in_data] > 0, "their bytes are counted (got #{core.stats[:in_data]})")
  sender.close
end

section 'Datagrams from unknown peers are dropped'
with_core do |core|
  sender = UDPSocket.new
  sender.send(udp_packet(0x96, 'orphan'), 0, Socket.pack_sockaddr_in(core.instance_variable_get(:@udp_port), '127.0.0.1'))
  received = wait_for{ core.stats[:in_data] > 0 }

  check(received, "the datagram is read off the socket (in_data #{core.stats[:in_data]})")
  check(core.stats[:in_packets] == 0, "but not processed (in_packets #{core.stats[:in_packets]})")
  check(core.instance_variable_get(:@thSock).alive?, "the socket thread survives it")
  sender.close
end

section 'Sending datagrams'
with_core do |core|
  # Bind where the peer's datagrams should land, which proves the +4 address end to end
  receiver = UDPSocket.new
  receiver.bind('127.0.0.1', 0)
  peer_udp_port = receiver.addr[1]
  server = core.add_server('127.0.0.1', peer_udp_port - 4)

  check(server.queue_udp_packet(ED2K::OP_EDONKEYPROT, 0x96, 'ping') == true, "queueing a datagram succeeds")

  got = nil
  begin
    Timeout.timeout(5) { got, _ = receiver.recvfrom(1024) }
  rescue Timeout::Error
  end
  check(got == udp_packet(0x96, 'ping').b, "it arrives with the right 2-byte header and payload (got #{got.inspect})")
  check(core.stats[:out_packets] == 1, "it's counted (got #{core.stats[:out_packets]})")
  check(core.stats[:out_data] == 6, "its bytes are counted (got #{core.stats[:out_data]})")

  # A burst, to confirm queue and send-token accounting stay balanced
  5.times{ |i| server.queue_udp_packet(ED2K::OP_EMULEPROT, 0x01, "m#{i}") }
  burst = []
  begin
    Timeout.timeout(5) { 5.times { data, _ = receiver.recvfrom(1024); burst << data } }
  rescue Timeout::Error
  end
  expected = (0...5).map{ |i| udp_packet(0x01, "m#{i}", ED2K::OP_EMULEPROT).b }
  check(burst.sort == expected.sort, "a burst of five all arrive intact (got #{burst.size})")

  receiver.close
end

section 'Sending without a known address is refused'
with_core do |core|
  # A client we've never seen an address for can't be sent to
  orphan = ED2K::Client.new(id: nil, port: 7000, core: core)
  check(orphan.udp_address.nil?, "a client with no IP has no UDP address")
  check(orphan.queue_udp_packet(ED2K::OP_EDONKEYPROT, 0x01, 'x') == false, "queueing a datagram to it is refused")
  check(core.instance_variable_get(:@thSock).alive?, "the socket thread is unaffected")
end

section 'An undeliverable datagram does not kill the socket thread'
# Sending to a closed port comes back as an ICMP unreachable, which the OS reports on the *next*
# receive rather than on the send. Letting that propagate used to take down the whole socket thread.
with_core do |core|
  closed = UDPSocket.new
  closed.bind('127.0.0.1', 0)
  dead_port = closed.addr[1]
  closed.close # Nothing is listening there any more

  server = core.add_server('127.0.0.1', dead_port - 4)
  3.times{ |i| server.queue_udp_packet(ED2K::OP_EDONKEYPROT, 0x96, "probe#{i}") }
  sleep 0.5 # Give the bounces time to come back and be reported

  check(core.instance_variable_get(:@thSock).alive?, "the socket thread is still alive")

  # And the core still works afterwards
  alive = core.add_server('127.0.0.2', 5000)
  parsed = Queue.new
  alive.define_singleton_method(:parse_edonkey_udp_packet){ |op, pl| parsed.push(pl.dup); pl }
  sender = UDPSocket.new
  sender.bind('127.0.0.2', 0)
  sender.send(udp_packet(0x96, 'still-here'), 0, Socket.pack_sockaddr_in(core.instance_variable_get(:@udp_port), '127.0.0.1'))
  check(pop_within(parsed) == 'still-here', "datagrams are still received afterwards")
  sender.close
end

report
