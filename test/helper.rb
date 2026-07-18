# Shared harness for the ed2k test suite.
#
# These are integration tests: they spin up real {ED2K::Core} instances with real threads and real
# sockets on the loopback interface, and drive them the way a client would. There's no mocking of
# the socket layer, so a passing test means the code actually works end to end. The flip side is
# that they're timing sensitive, hence the generous timeouts and the {wait_for} helper.
#
# Every test file requires this and ends with a call to {report}, which sets the exit status.

require_relative '../lib/ed2k.rb'
require 'socket'
require 'timeout'

$stdout.sync = true

$checks   = 0
$failures = []

# Print a section header to group related checks.
# @param name [String] The name of the group of checks that follow.
def section(name)
  puts "\n-- #{name} --"
end

# Assert a condition, recording and reporting the result.
# @param cond [Boolean] The condition that ought to hold.
# @param msg [String] Description of what's being checked, phrased as the expected outcome.
# @return [Boolean] The condition itself, so it can be used to guard dependent checks.
def check(cond, msg)
  $checks += 1
  $failures << msg if !cond
  puts "#{cond ? '  ok  ' : ' FAIL '} #{msg}"
  cond
end

# Print an informational line that isn't a pass/fail assertion, e.g. a measurement.
# @param msg [String] The text to print.
def note(msg)
  puts "  ..    #{msg}"
end

# Summarize the run and exit with a status code reflecting it. Must be the last thing a test does.
def report
  if $failures.empty?
    puts "\nALL OK (#{$checks} checks)"
    exit(0)
  end
  puts "\n#{$failures.size}/#{$checks} FAILED:"
  $failures.each{ |msg| puts "  - #{msg}" }
  exit(1)
end

# Find a port that's currently free. There's an unavoidable race between releasing the probe socket
# and the caller binding it, so this is a best effort rather than a reservation.
# @return [Integer] A port number that was free a moment ago.
def free_port
  probe = TCPServer.new('127.0.0.1', 0)
  port = probe.addr[1]
  probe.close
  port
end

# Spin up a running core, hand it to the block, and always stop it afterwards. The block also
# receives an array that accumulates every log line the core emits, as `[level, message]` pairs,
# which lets tests assert on logging without printing anything themselves.
# @param log_level [Integer] Level for the core's own stdout logger. Silent by default.
# @yieldparam core [ED2K::Core] The started core.
# @yieldparam logs [Array<Array(Integer,String)>] Log lines captured so far.
def with_core(log_level: ED2K::Core::LOG_LEVEL_NONE)
  core = ED2K::Core.new(log_level: log_level)
  logs = []
  core.add_logger{ |msg, level| logs << [level, msg] }
  core.config(udp_port: free_port)
  core.start(free_port)
  yield(core, logs)
ensure
  core.stop if core
end

# Select the messages logged at a given level.
# @param logs [Array] The captured log pairs, as handed to the {with_core} block.
# @param level [Integer] The log level to filter by, e.g. {ED2K::Core::LOG_LEVEL_WARNING}.
# @return [Array<String>] The matching messages.
def logs_at(logs, level)
  logs.select{ |lvl, _| lvl == level }.map(&:last)
end

# Build a well-formed ed2k TCP packet, header included.
# @param opcode [Integer] The packet's opcode.
# @param payload [String] The packet's payload.
# @param protocol [Integer] The protocol byte.
# @return [String] The serialized packet.
def tcp_packet(opcode, payload = '', protocol = ED2K::OP_EDONKEYPROT)
  [protocol, payload.bytesize + 1, opcode].pack('CL<C') + payload
end

# Build a well-formed ed2k UDP datagram, header included. Unlike TCP there's no size field.
# @param opcode [Integer] The datagram's opcode.
# @param payload [String] The datagram's payload.
# @param protocol [Integer] The protocol byte.
# @return [String] The serialized datagram.
def udp_packet(opcode, payload = '', protocol = ED2K::OP_EDONKEYPROT)
  [protocol, opcode].pack('CC') + payload
end

# Block until a condition holds, polling until it does or the timeout elapses. Preferable to a bare
# sleep, since it returns as soon as the condition is met and states the intent explicitly.
# @param timeout [Float] Maximum time in seconds to wait.
# @param interval [Float] Time in seconds between polls.
# @return [Boolean] Whether the condition became true within the timeout.
def wait_for(timeout: 5, interval: 0.02)
  deadline = Time.now + timeout
  while Time.now < deadline
    return true if yield
    sleep(interval)
  end
  false
end

# Pop an item from a queue, giving up after a timeout instead of blocking the whole suite forever.
# @param queue [Queue] The queue to pop from.
# @param timeout [Float] Maximum time in seconds to wait for an item.
# @return [Object,nil] The item, or `nil` if none arrived in time.
def pop_within(queue, timeout: 5)
  Timeout.timeout(timeout) { queue.pop }
rescue Timeout::Error
  nil
end

# Start a fake peer listening on the loopback interface, for the core to connect out to. Returns the
# listener along with the port it bound to, so tests don't have to guess a free one.
# @param ip [String] The loopback address to bind to. Distinct addresses allow several peers to
#        coexist, which matters because clients are keyed by IP alone.
# @return [Array(TCPServer,Integer)] The listening socket and its port.
def fake_peer(ip = '127.0.0.1')
  listener = TCPServer.new(ip, 0)
  [listener, listener.addr[1]]
end
