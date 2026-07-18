# The socket thread: how promptly it reacts to queued work, and how it shares itself between peers.

require_relative 'helper.rb'

section 'Queued packets are sent without waiting for the select timeout'
# The socket thread blocks in select for up to TIMEOUT_WAIT. Without a waker to interrupt it, a
# packet queued right after it went to sleep would sit there for up to that long.
with_core do |core|
  listener, port = fake_peer
  server = core.add_server('127.0.0.1', port)
  check(core.connect(server), "connected to the fake peer")
  remote = listener.accept

  # Let the socket thread settle into select with nothing to do
  sleep 0.3

  latencies = 3.times.map do
    started = Time.now
    server.queue_tcp_packet(ED2K::OP_EDONKEYPROT, 0x01, 'wakeywakey')
    remote.readpartial(4096)
    elapsed = Time.now - started
    sleep 0.3 # Let it fall back into select before the next round
    elapsed
  end

  latencies.each_with_index{ |t, i| note("send %d took %.1f ms" % [i + 1, t * 1000]) }
  worst = latencies.max
  check(worst < ED2K::Core::TIMEOUT_WAIT / 2,
        "every send beat half the select timeout (worst %.1f ms, timeout %d ms)" % [worst * 1000, ED2K::Core::TIMEOUT_WAIT * 1000])

  remote.close
  listener.close
end

section 'A new outgoing connection is picked up promptly'
with_core do |core|
  listener, port = fake_peer
  server = core.add_server('127.0.0.1', port)
  sleep 0.3 # Socket thread is idle in select

  core.connect(server)
  remote = listener.accept
  started = Time.now
  server.queue_tcp_packet(ED2K::OP_EDONKEYPROT, 0x01, 'hello')
  remote.readpartial(4096)
  check(Time.now - started < ED2K::Core::TIMEOUT_WAIT / 2, "a freshly added connection is monitored right away")

  remote.close
  listener.close
end

section 'One busy peer cannot monopolize the thread'
# Both peers saturate the link at once, so both always have a backlog waiting. Reading each socket
# to exhaustion would empty one peer entirely before touching the other; a per-round budget bounds
# how long either can hold the thread. Measured as the longest unbroken run of packets from one
# peer, which unlike "who finished first" doesn't depend on when each peer happened to start.
DURATION = 3.0
PAYLOAD  = 'x' * 900

with_core do |core|
  # Distinct loopback IPs, since clients are keyed by IP alone
  peers = ['127.0.0.1', '127.0.0.2'].map do |ip|
    listener, port = fake_peer(ip)
    [ip, listener, port]
  end

  remotes = []
  acceptor = Thread.new{ peers.each{ |_, listener, _| remotes << listener.accept } }
  servers = peers.map{ |ip, _, port| core.add_server(ip, port) }
  servers.each{ |server| core.connect(server) }
  acceptor.join

  order = Queue.new
  servers.each_with_index do |server, i|
    server.define_singleton_method(:parse_edonkey_tcp_packet){ |op, pl| order.push(i); pl }
  end

  stop_at = Time.now + DURATION
  writers = remotes.map do |socket|
    Thread.new do
      blob = tcp_packet(0x01, PAYLOAD)
      begin
        socket.write(blob) while Time.now < stop_at
      rescue StandardError # The peer goes away when the core stops
      end
    end
  end
  writers.each(&:join)
  sleep 1.0 # Let the pipeline drain

  sequence = []
  sequence << order.pop(true) while !order.empty?

  counts = [sequence.count(0), sequence.count(1)]
  note("parsed #{counts[0]} + #{counts[1]} = #{sequence.size} packets")
  check(counts.all?{ |c| c > 0 }, "both peers got through (got #{counts.inspect})")

  longest = 0
  run = 0
  previous = nil
  sequence.each do |peer|
    run = peer == previous ? run + 1 : 1
    previous = peer
    longest = run if run > longest
  end

  # One budget's worth of these packets is the natural bound on an uninterrupted run
  budget = ED2K::Core::TCP_READ_SIZE / (PAYLOAD.bytesize + ED2K::PACKET_HEADER_SIZE)
  note("longest unbroken run: #{longest} packets, one budget is about #{budget}")
  check(longest < budget * 4, "no peer held the thread for anywhere near a full backlog (#{longest} vs budget #{budget})")

  balance = counts.min.to_f / counts.max
  note("throughput balance: #{(balance * 100).round(1)}%")
  check(balance > 0.8, "both peers moved comparable amounts of data")

  remotes.each(&:close)
  peers.each{ |_, listener, _| listener.close }
end

report
