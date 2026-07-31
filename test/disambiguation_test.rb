# Telling apart several servers that share a single IP address.
#
# Incoming messages only carry the address a server is sending from, never the port it listens on,
# which is what identifies it. When several known servers share an IP the address alone is therefore
# ambiguous, and we fall back on the fact that servers essentially only contact us to answer
# something we asked: whichever candidate is awaiting an answer is the one that sent it.
#
# `pending_login=`, `parse_id_change` and `parse_reject` are internal to Server, so the tests reach them through
# `send` to set up scenarios without making them part of the public API.

require_relative 'helper.rb'

ERROR   = ED2K::Core::LOG_LEVEL_ERROR
WARNING = ED2K::Core::LOG_LEVEL_WARNING
DEBUG   = ED2K::Core::LOG_LEVEL_DEBUG

with_core do |core, logs|
  section 'Adding a server on an already known IP is logged'
  core.add_server('9.9.9.9', 4661)
  before = logs.size
  core.add_server('9.9.9.9', 4665)
  shared = logs_at(logs[before..], DEBUG).select{ |msg| msg.include?('already known IP') }
  check(shared.size == 1, "one debug line is logged (got #{shared.size})")
  check(shared.first.to_s.include?('4661') && shared.first.to_s.include?('4665'), "it lists both ports")

  before = logs.size
  core.add_server('8.8.8.8', 4661)
  check(logs_at(logs[before..], DEBUG).none?{ |msg| msg.include?('already known IP') },
        "nothing is logged for a server on a fresh IP")

  section 'Breaking the tie'
  a = core.get_server(ip: '9.9.9.9', port: 4661)
  b = core.get_server(ip: '9.9.9.9', port: 4665)
  pending = ->(server){ server.pending_login }

  check(core.get_server(ip: '8.8.8.8', prefer: pending).tcp_port == 4661,
        "a lone server at an IP resolves without needing the hint")

  a.send(:pending_login=, false)
  b.send(:pending_login=, false)
  check(core.get_server(ip: '9.9.9.9', prefer: pending).equal?(a), "with nobody pending, the first candidate wins")

  b.send(:pending_login=, true)
  check(core.get_server(ip: '9.9.9.9', prefer: pending).equal?(b), "a single pending candidate wins, even if not first")

  a.send(:pending_login=, true)
  check(core.get_server(ip: '9.9.9.9', prefer: pending).equal?(a), "with everyone pending it's ambiguous, first wins")
end

with_core do |core|
  section 'Pending login lifecycle'
  server = core.add_server('7.7.7.7', 4661)
  server.tcp_setup
  check(server.pending_login == false, "a fresh server isn't awaiting a login answer")

  server.send_login("\x00" * 16, 'tester')
  check(server.pending_login == true, "sending a login starts awaiting one")
  server.send(:parse_id_change, [12345, 0, 0, 0, 0].pack('L<5'))
  check(server.pending_login == false, "being assigned an ID answers it")

  server.send_login("\x00" * 16, 'tester')
  server.send(:parse_reject)
  check(server.pending_login == false, "a rejection also stops the wait")

  section 'Pending login expires'
  # An answer may never arrive, and a flag stuck at true would skew every later tie-break.
  check(ED2K::Server::TIMEOUT_LOGIN.is_a?(Numeric), "Server::TIMEOUT_LOGIN is defined (#{ED2K::Server::TIMEOUT_LOGIN}s)")
  server.send_login("\x00" * 16, 'tester')
  check(server.pending_login == true, "pending right after sending")

  server.instance_variable_set(:@login_time, Time.now - ED2K::Server::TIMEOUT_LOGIN + 5)
  check(server.pending_login == true, "still pending just inside the timeout")

  server.instance_variable_set(:@login_time, Time.now - ED2K::Server::TIMEOUT_LOGIN - 1)
  check(server.pending_login == false, "no longer pending once the timeout elapses")
  check(server.instance_variable_get(:@pending_login) == false, "the expiry sticks instead of being recomputed each read")

  stale = core.add_server('5.5.5.5', 4661)
  fresh = core.add_server('5.5.5.5', 4665)
  fresh.send(:pending_login=, true)
  fresh.instance_variable_set(:@login_time, Time.now - ED2K::Server::TIMEOUT_LOGIN - 1)
  check(core.get_server(ip: '5.5.5.5', prefer: ->(s){ s.pending_login }).equal?(stale),
        "a stale pending login no longer captures the tie-break")

  # UDP is currently disabled in the core, so its pending-answer bookkeeping can't be exercised; this section runs
  # again automatically once UDP is restored.
  if udp_enabled?
    section 'Pending UDP answer lifecycle'
    peer = core.add_server('6.6.6.6', 4661)
    check(peer.pending_udp? == false, "a fresh server isn't awaiting a UDP answer")
    peer.queue_udp_packet(ED2K::OP_EDONKEYPROT, ED2K::OP_GLOBSERVSTATREQ, 'q')
    check(peer.pending_udp? == true, "sending a UDP query starts awaiting one")
    peer.udp_answered
    check(peer.pending_udp? == false, "receiving the answer stops the wait")
    peer.udp_answered
    check(peer.pending_udp? == false, "the count never falls below zero")
  end
end

# NOTE: the two "inbound connection" sections that used to live here have been removed. They tested attributing an
# inbound TCP connection to one of several servers sharing an IP, but inbound connections are now always treated as
# clients (see the "Accepting an incoming connection" section of keying_test.rb), so that disambiguation no longer
# applies to TCP. The server tie-break above still governs UDP datagrams once UDP is re-enabled.

# Unlike a TCP connection, a datagram is kept: for many replies (source requests, global searches)
# the exact server it came from doesn't matter. For others (status, description) it does, hence the
# warning rather than silence.
if udp_enabled?
  section 'An ambiguous datagram warns but is still delivered'
  with_core do |core, logs|
    first  = core.add_server('127.0.0.1', 4661)
    second = core.add_server('127.0.0.1', 4665)
    seen = Queue.new
    [first, second].each do |server|
      server.define_singleton_method(:parse_edonkey_udp_packet) do |opcode, payload|
        seen.push([self, opcode, payload.dup])
        payload
      end
    end

    sender = UDPSocket.new
    destination = Socket.pack_sockaddr_in(core.instance_variable_get(:@udp_port), '127.0.0.1')
    sender.send(udp_packet(ED2K::OP_GLOBSERVSTATREQ, 'hi'), 0, destination)

    got = pop_within(seen)
    check(got && got[1] == ED2K::OP_GLOBSERVSTATREQ && got[2] == 'hi', "the datagram is delivered rather than dropped")
    check(got && got[0].equal?(first), "it falls through to the first server")
    check(logs_at(logs, WARNING).count{ |msg| msg.include?('several known servers') } == 1, "a warning is logged")

    # With one server uniquely awaiting an answer, the tie resolves and the warning goes away
    logs.clear
    second.queue_udp_packet(ED2K::OP_EDONKEYPROT, ED2K::OP_GLOBSERVSTATREQ, 'q')
    sender.send(udp_packet(ED2K::OP_GLOBSERVSTATREQ, 'yo'), 0, destination)

    got = pop_within(seen)
    check(got && got[0].equal?(second), "the datagram reaches the server awaiting a UDP answer")
    check(logs_at(logs, WARNING).none?{ |msg| msg.include?('several known servers') }, "no warning when the tie resolves")
    check(second.pending_udp? == false, "receiving it clears the pending state")
    sender.close
  end
end

report
