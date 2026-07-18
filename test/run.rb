# Runs the whole ed2k test suite.
#
#   ruby test/run.rb            # run every test
#   ruby test/run.rb tag udp    # run only the tests whose name matches one of the given words
#
# Each test file runs in its own process, so a test that crashes the interpreter or wedges a socket
# thread can't take the rest of the suite down with it, and leaked ports die with the process.
# Output is streamed as it arrives, and a hung test is killed once it exceeds the timeout.

require 'timeout'

TIMEOUT = 180 # Maximum time in seconds a single test file may run for

files = Dir[File.join(__dir__, '*_test.rb')].sort
files.select!{ |f| ARGV.any?{ |arg| File.basename(f).include?(arg) } } if !ARGV.empty?

if files.empty?
  puts ARGV.empty? ? "No test files found in #{__dir__}" : "No test files match #{ARGV.join(', ')}"
  exit(1)
end

results = {}
width = files.map{ |f| File.basename(f).size }.max

files.each do |file|
  name = File.basename(file)
  puts "\n#{'=' * 70}\n#{name}\n#{'=' * 70}"

  started = Time.now
  pid = Process.spawn(RbConfig.ruby, file, chdir: File.expand_path('..', __dir__))
  status = nil
  begin
    Timeout.timeout(TIMEOUT) { _, status = Process.wait2(pid) }
    results[name] = status.success? ? :pass : :fail
  rescue Timeout::Error
    Process.kill('KILL', pid) rescue nil
    Process.wait(pid) rescue nil
    puts "\n!! timed out after #{TIMEOUT}s"
    results[name] = :timeout
  end
  results["#{name}_time"] = Time.now - started
end

puts "\n#{'=' * 70}\nSUMMARY\n#{'=' * 70}"
results.reject{ |k, _| k.end_with?('_time') }.each do |name, result|
  label = { pass: '  ok  ', fail: ' FAIL ', timeout: ' HUNG ' }[result]
  puts "#{label} %-#{width}s  %.1fs" % [name, results["#{name}_time"]]
end

failed = results.count{ |k, v| !k.end_with?('_time') && v != :pass }
puts failed.zero? ? "\nAll #{files.size} test files passed" : "\n#{failed}/#{files.size} test files failed"
exit(failed.zero? ? 0 : 1)
