# Optional global transfer rate limits, enforced by a token bucket per direction.
#
# Two things have to hold, and the second is the easier one to get wrong: the achieved rate must stay at or below the
# configured limit, and it must actually *reach* it whenever the peers can collectively supply it. A limiter that
# throttles a peer more than necessary, or that lets the socket thread oversleep, would pass the first and fail the
# second, so every transfer case below checks both bounds.

require_relative 'helper.rb'

# How far the achieved rate may stray from the limit before we call it a failure. The upper bound accounts for the
# bucket's burst capacity landing inside the measurement window; the lower one for scheduling jitter and the fact that
# Ruby has to parse everything it reads.
OVER_TOLERANCE  = 1.20
UNDER_TOLERANCE = 0.80

MEASURE = 2.5  # Seconds to measure a transfer over, once it's up to speed
WARMUP  = 0.75 # Seconds to let a transfer settle before measuring

# Tear a scenario down. The order matters: a writer feeding a throttled core is blocked inside a write on a socket
# whose buffers are full, and it only notices the stop signal once the core has drained them, which at these rates
# takes tens of seconds. Closing the peer's end first makes that write fail immediately and the thread finish at once.
# @param stop [Queue] The stop signal the threads watch.
# @param threads [Array<Thread>] The threads to wind down.
# @param remotes [Array<TCPSocket>] The peers' ends of the connections.
# @param listeners [Array<TCPServer>] The listening sockets.
def teardown(stop, threads, remotes, listeners)
  stop.push(true)
  remotes.each{ |socket| socket.close rescue nil }
  threads.each{ |thread| thread.join(5) || thread.kill }
  listeners.each{ |listener| listener.close rescue nil }
end

# Saturate a set of sockets with valid packets until told to stop.
# @param sockets [Array<TCPSocket>] The sockets to write to.
# @param stop [Queue] Pushing anything here ends the writers.
# @return [Array<Thread>] The writer threads.
def saturate(sockets, stop)
  blob = tcp_packet(0x01, 'x' * 900)
  sockets.map do |socket|
    Thread.new do
      begin
        socket.write(blob) while stop.empty?
      rescue StandardError # The core goes away at the end of the test
      end
    end
  end
end

# Connect the core to a number of fake peers, and hand back the peers' ends of those connections.
# @param core [ED2K::Core] The core to connect.
# @param count [Integer] How many peers to set up. Each gets its own loopback IP, since clients are keyed by IP.
# @return [Array(Array<TCPSocket>,Array<TCPServer>,Array<ED2K::Server>)] Remote ends, listeners and server objects.
def connect_peers(core, count)
  listeners = count.times.map{ |i| fake_peer("127.0.0.#{i + 1}") }
  remotes = []
  acceptor = Thread.new{ listeners.each{ |listener, _| remotes << listener.accept } }
  servers = listeners.each_with_index.map{ |(_, port), i| core.add_server("127.0.0.#{i + 1}", port) }
  servers.each{ |server| core.connect(server) }
  acceptor.join
  [remotes, listeners.map(&:first), servers]
end

# Measure the rate at which a statistic grows, over a fixed window after a warmup.
# @param core [ED2K::Core] The core to observe.
# @param stat [Symbol] The statistic to sample, e.g. `:in_data`.
# @return [Float] The observed rate in bytes per second.
def measure_rate(core, stat)
  sleep WARMUP
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  before  = core.stats[stat]
  sleep MEASURE
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  (core.stats[stat] - before) / elapsed
end

# Assert that an observed rate sits tightly around a limit, in both directions.
# @param observed [Float] The measured rate in bytes per second.
# @param limit [Integer] The configured limit in bytes per second.
# @param what [String] Description of the scenario, for the check messages.
def check_rate(observed, limit, what)
  note("%s: %.0f KB/s measured against a %.0f KB/s limit (%.0f%%)" %
       [what, observed / 1024, limit / 1024.0, 100.0 * observed / limit])
  check(observed <= limit * OVER_TOLERANCE,
        "#{what} stays at or below the limit (#{(observed / 1024).round} <= #{(limit * OVER_TOLERANCE / 1024).round} KB/s)")
  check(observed >= limit * UNDER_TOLERANCE,
        "#{what} actually reaches the limit (#{(observed / 1024).round} >= #{(limit * UNDER_TOLERANCE / 1024).round} KB/s)")
end

section 'Token bucket in isolation'
unlimited = ED2K::TokenBucket.new(0)
check(unlimited.limited? == false, "a rate of zero means unlimited")
check(unlimited.take(1_000_000) == 1_000_000, "an unlimited bucket grants whatever is asked for")
check(unlimited.wait_time == 0.0, "and never asks anyone to wait")

RATE = 10_000
CAPACITY = [(RATE * ED2K::TokenBucket::BURST_TIME).round, ED2K::TokenBucket::MIN_CAPACITY].max

bucket = ED2K::TokenBucket.new(RATE)
check(bucket.limited?, "a non-zero rate is a limit")
check(bucket.take(RATE) == 0, "a fresh bucket is empty, so it grants nothing")

# A slow bucket, so that nothing meaningful accrues between one call and the next
slow = ED2K::TokenBucket.new(100)
check(slow.take(1000) == 0, "an empty bucket grants nothing")
check(slow.wait_time > 0, "and reports how long until it can (#{slow.wait_time.round(2)}s)")

sleep 0.3
granted = bucket.take(RATE)
check(granted > 0 && granted <= CAPACITY,
      "after waiting it grants what accrued, capped by its capacity (got #{granted}, capacity #{CAPACITY})")

bucket.refund(granted)
check(bucket.take(RATE) >= granted, "refunded tokens are available again")

# Grants are batched rather than dribbled out a byte at a time, which is what keeps a throttled
# core from waking up thousands of times a second
tiny = ED2K::TokenBucket.new(64 * 1024)
sleep 0.15 # Comfortably longer than the interval between grants at this rate
check(tiny.take(64 * 1024) >= 1024, "a grant is a worthwhile chunk, not a handful of bytes")
check(tiny.take(64 * 1024) == 0, "and nothing more is granted until enough has accrued again")
check(tiny.wait_time > 0.001, "so the wait between grants is a real sleep (#{(tiny.wait_time * 1000).round(1)}ms)")

# Debt from ungated traffic has to be repaid before anything else is granted
debt = ED2K::TokenBucket.new(10_000)
sleep 0.3
debt.deduct(1_000_000)
check(debt.take(1000) == 0, "a bucket in debt grants nothing")
check(debt.wait_time > 1, "and reports a long wait until it recovers (#{debt.wait_time.round(1)}s)")

section 'Defaults'
check(ED2K::Core::DEFAULT_DOWN_RATE == 0, "the default download rate is unlimited")
check(ED2K::Core::DEFAULT_UP_RATE == 0, "the default upload rate is unlimited")
with_core do |core|
  check(core.down_rate == 0, "a core defaults to an unlimited download rate")
  check(core.up_rate == 0, "a core defaults to an unlimited upload rate")
end

section 'Configuring'
core = ED2K::Core.new(log_level: ED2K::Core::LOG_LEVEL_NONE, down_rate: 1024, up_rate: 2048)
check(core.down_rate == 1024, "the download rate can be set on construction")
check(core.up_rate == 2048, "so can the upload rate")
core.config(down_rate: 4096)
check(core.down_rate == 4096, "the download rate can be changed on a running core")
check(core.up_rate == 2048, "without disturbing the upload rate")

section 'An unlimited core is not throttled'
# The point of comparison for everything below: with no limit the same setup goes far faster.
unthrottled = nil
with_core do |core|
  remotes, listeners, _ = connect_peers(core, 1)
  stop = Queue.new
  writers = saturate(remotes, stop)
  unthrottled = measure_rate(core, :in_data)
  teardown(stop, writers, remotes, listeners)
  note("unlimited download ran at %.1f MB/s" % (unthrottled / 1024.0 / 1024))
  check(unthrottled > 1024 * 1024, "an unlimited core downloads at well over 1 MB/s")
end

section 'Download limit, single peer'
LIMIT = 512 * 1024
with_core do |core|
  core.config(down_rate: LIMIT)
  remotes, listeners, _ = connect_peers(core, 1)
  stop = Queue.new
  writers = saturate(remotes, stop)
  check_rate(measure_rate(core, :in_data), LIMIT, "one peer downloading")
  teardown(stop, writers, remotes, listeners)
end

section 'Download limit is global, not per peer'
# Three peers all pulling at once must still add up to the single configured limit, and must still reach it.
with_core do |core|
  core.config(down_rate: LIMIT)
  remotes, listeners, _ = connect_peers(core, 3)
  stop = Queue.new
  writers = saturate(remotes, stop)
  check_rate(measure_rate(core, :in_data), LIMIT, "three peers downloading")
  teardown(stop, writers, remotes, listeners)
end

section 'A different download limit'
SLOW = 128 * 1024
with_core do |core|
  core.config(down_rate: SLOW)
  remotes, listeners, _ = connect_peers(core, 2)
  stop = Queue.new
  writers = saturate(remotes, stop)
  check_rate(measure_rate(core, :in_data), SLOW, "two peers at a lower limit")
  teardown(stop, writers, remotes, listeners)
end

section 'Upload limit'
with_core do |core|
  core.config(up_rate: LIMIT)
  remotes, listeners, servers = connect_peers(core, 2)

  # Keep the outgoing queues full, and keep draining the peers' ends so the kernel buffers never become the bottleneck
  stop = Queue.new
  feeder = Thread.new do
    payload = 'x' * 4000
    while stop.empty?
      servers.each{ |server| server.queue_tcp_packet(ED2K::OP_EDONKEYPROT, 0x01, payload.dup) }
      sleep 0.002
    end
  end
  drainers = remotes.map{ |socket| Thread.new{ socket.readpartial(65536) while stop.empty? rescue nil } }

  check_rate(measure_rate(core, :out_data), LIMIT, "two peers uploading")

  teardown(stop, [feeder] + drainers, remotes, listeners)
end

section 'Both directions limited at once'
with_core do |core|
  core.config(down_rate: SLOW, up_rate: SLOW)
  remotes, listeners, servers = connect_peers(core, 2)

  stop = Queue.new
  writers = saturate(remotes, stop)
  feeder = Thread.new do
    payload = 'x' * 4000
    while stop.empty?
      servers.each{ |server| server.queue_tcp_packet(ED2K::OP_EDONKEYPROT, 0x01, payload.dup) }
      sleep 0.002
    end
  end

  sleep WARMUP
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  down_before, up_before = core.stats[:in_data], core.stats[:out_data]
  sleep MEASURE
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

  check_rate((core.stats[:in_data] - down_before) / elapsed, SLOW, "download while both are limited")
  # Uploads share the thread with a saturated download here, so only the ceiling is meaningful
  up_rate = (core.stats[:out_data] - up_before) / elapsed
  note("upload alongside it ran at %.0f KB/s" % (up_rate / 1024))
  check(up_rate <= SLOW * OVER_TOLERANCE, "upload stays at or below its limit too")

  teardown(stop, writers + [feeder], remotes, listeners)
end

section 'Throttling does not burn CPU'
# A throttled core must sleep until its allowance recovers, not spin in select reporting ready sockets it declines to
# read. Comparing process CPU time against wall time catches a busy loop immediately.
with_core do |core|
  core.config(down_rate: 64 * 1024)
  remotes, listeners, _ = connect_peers(core, 2)
  stop = Queue.new
  writers = saturate(remotes, stop)

  sleep WARMUP
  cpu_before  = Process.times
  wall_before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  sleep MEASURE
  cpu = (Process.times.utime - cpu_before.utime) + (Process.times.stime - cpu_before.stime)
  wall = Process.clock_gettime(Process::CLOCK_MONOTONIC) - wall_before

  note("used %.0f%% of a core while throttled to 64 KB/s" % (100.0 * cpu / wall))
  check(cpu / wall < 0.5, "a heavily throttled core stays well under a full core of CPU")

  teardown(stop, writers, remotes, listeners)
end

report
