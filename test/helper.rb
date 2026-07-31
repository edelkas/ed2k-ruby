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

# Whether UDP is currently built into the core. It's toggled as a unit (Server/Client#udp_setup and
# Core#init_udp_socket are commented out together), so a freshly built peer having a UDP address is a faithful proxy
# for the whole UDP path being live. Lets the UDP-dependent tests skip while UDP is disabled and light up again on
# their own once it's restored, instead of hard-failing against a feature that's deliberately off.
# @return [Boolean]
def udp_enabled?
  ED2K::Server.new('127.0.0.1', 5000).udp_port == 5004
end

# Announce that a test file is being skipped and finish it as a pass, so a deliberately-disabled feature doesn't
# read as a failure in the suite. Call it in place of {report}.
# @param reason [String] Why the file is skipped.
def skip_file(reason)
  puts "\nSKIPPED: #{reason}"
  exit(0)
end

# Find a port that's currently free. There's an unavoidable race between releasing the probe socket
# and the caller binding it, so this is a best effort rather than a reservation.
#
# The probe has to use the same protocol the caller intends to bind, because the two aren't
# interchangeable: on Windows, Hyper-V and WinNAT reserve whole blocks of ports per protocol (see
# `netsh interface ipv4 show excludedportrange protocol=udp`), and binding one of those fails with
# EACCES rather than EADDRINUSE. A TCP probe therefore happily returns a port that UDP may not have.
# @param udp [Boolean] Whether the port is destined for a UDP socket rather than a TCP one.
# @return [Integer] A port number that was free a moment ago for the requested protocol.
def free_port(udp: false)
  probe = udp ? UDPSocket.new : TCPServer.new('127.0.0.1', 0)
  probe.bind('127.0.0.1', 0) if udp
  port = probe.addr[1]
  probe.close
  port
end

# Spin up a running core, hand it to the block, and always stop it afterwards. The block also
# receives an array that accumulates every log line the core emits, as `[level, message]` pairs,
# which lets tests assert on logging without printing anything themselves.
#
# The core's own stdout logger is disabled (tests capture via the block instead), and the level is left at DEBUG so
# the capture logger receives every message; the core gates on `@log_level` before any logger runs, so a stricter
# level here would silently drop lines the tests want to inspect. Pass a stricter `log_level` only to test that gating.
# @param log_level [Integer] Level below which messages are dropped before reaching the capture logger.
# @yieldparam core [ED2K::Core] The started core.
# @yieldparam logs [Array<Array(Integer,String)>] Log lines captured so far.
def with_core(log_level: ED2K::Core::LOG_LEVEL_DEBUG)
  core = ED2K::Core.new(default_logger: false, log_level: log_level)
  logs = []
  core.add_logger{ |msg, level| logs << [level, msg] }
  core.config(udp_port: free_port(udp: true))
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
