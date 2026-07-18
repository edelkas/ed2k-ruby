# The packet thread and the ready queue that feeds it.
#
# Every received packet pushes one scheduling token onto the core's ready queue, and the packet
# thread pops tokens and processes exactly one packet each. The interesting cases are the ones where
# tokens and packets get out of step: a peer that disconnects and has its queue cleared, or a token
# left over for a queue that's already empty.

require_relative 'helper.rb'

section 'Packets are processed in order, interleaved across peers'
with_core do |core|
  a = core.add_server('127.0.0.1', 4661)
  b = core.add_server('127.0.0.2', 4661)
  [a, b].each(&:tcp_setup)

  processed = { a => [], b => [] }
  done = Queue.new
  [[a, 'a'], [b, 'b']].each do |server, tag|
    server.define_singleton_method(:parse_edonkey_udp_packet) do |opcode, payload|
      processed[self] << payload.dup
      done.push(true)
      payload
    end
  end

  count = 50
  count.times do |i|
    a.enqueue_incoming_udp(udp_packet(0x01, "a#{i}"))
    core.schedule_packet(a, :udp)
    b.enqueue_incoming_udp(udp_packet(0x01, "b#{i}"))
    core.schedule_packet(b, :udp)
  end

  drained = wait_for(timeout: 10){ processed[a].size + processed[b].size == count * 2 }
  check(drained, "every queued packet was processed (got #{processed[a].size} + #{processed[b].size})")
  check(processed[a] == count.times.map{ |i| "a#{i}" }, "the first peer's packets kept their order")
  check(processed[b] == count.times.map{ |i| "b#{i}" }, "the second peer's packets kept their order")
end

section 'A token for a cleared queue is harmless'
# When a peer disconnects its incoming queue is cleared and closed, but tokens already on the ready
# queue still point at it. Popping from a closed empty queue yields nil rather than raising, so an
# unguarded token would have been processed as a nil packet.
with_core do |core|
  server = core.add_server('127.0.0.1', 4661)
  server.tcp_setup
  attempts = Queue.new
  server.define_singleton_method(:parse_edonkey_udp_packet){ |op, pl| attempts.push(pl); pl }

  queue = server.instance_variable_get(:@udp_incoming_queue)
  server.enqueue_incoming_udp(udp_packet(0x01, 'gone'))
  queue.clear
  queue.close
  core.schedule_packet(server, :udp) # Stale token, its packet no longer exists

  sleep 0.4
  check(core.instance_variable_get(:@thPack).alive?, "the packet thread survives the stale token")
  check(attempts.empty?, "nothing was handed to the parser")
end

section 'A token for an empty open queue is harmless'
with_core do |core|
  server = core.add_server('127.0.0.1', 4661)
  server.tcp_setup
  attempts = Queue.new
  server.define_singleton_method(:parse_edonkey_udp_packet){ |op, pl| attempts.push(pl); pl }

  core.schedule_packet(server, :udp) # A token with no packet behind it at all

  sleep 0.4
  check(core.instance_variable_get(:@thPack).alive?, "the packet thread survives it")
  check(attempts.empty?, "nothing was handed to the parser")

  # The connection still works normally afterwards
  server.enqueue_incoming_udp(udp_packet(0x01, 'after'))
  core.schedule_packet(server, :udp)
  check(pop_within(attempts) == 'after', "a real packet is still processed afterwards")
end

section 'The packet thread idles without spinning'
with_core do |core|
  # With an empty ready queue the thread should be blocked in pop, not burning CPU. A blocked thread
  # reports as sleeping; a spinning one would be runnable.
  sleep 0.3
  thread = core.instance_variable_get(:@thPack)
  check(thread.alive?, "the packet thread is alive")
  check(thread.status == 'sleep', "and blocked rather than spinning (status #{thread.status.inspect})")
end

section 'Both threads stop cleanly'
core = ED2K::Core.new(log_level: ED2K::Core::LOG_LEVEL_NONE)
core.config(udp_port: free_port)
core.start(free_port)
socket_thread = core.instance_variable_get(:@thSock)
packet_thread = core.instance_variable_get(:@thPack)

started = Time.now
check(core.stop == true, "stopping the core reports success")
elapsed = Time.now - started

note("stopped in %.1f ms" % (elapsed * 1000))
check(!socket_thread.alive?, "the socket thread finished")
check(!packet_thread.alive?, "the packet thread finished, i.e. its blocking pop was unblocked")
check(elapsed < ED2K::Core::THREAD_TIMEOUT * 2, "it didn't have to wait for a timeout to do so")

report
