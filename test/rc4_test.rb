# The RC4 cipher behind protocol obfuscation ({ED2K::Obfuscation::RC4}).
#
# There are two implementations of the same cipher: a pure Ruby one and a native C one from the
# extension. They share their whole state (@S, @i, @j) in the same format, so the point of most of
# these checks is that the two are indistinguishable: identical ciphertext, identical state, and
# interchangeable even in the middle of a stream.
#
# A benchmark comparing the two lives at the end. It's slow (a minute or so, since the pure Ruby side
# is ~100x slower), so it's skipped unless RC4_BENCH is set in the environment:
#
#   ruby test/rc4_test.rb              # correctness only (also how the full suite runs it)
#   RC4_BENCH=1 ruby test/rc4_test.rb  # correctness, then the benchmark

require_relative 'helper.rb'
require 'benchmark'

RC4 = ED2K::Obfuscation::RC4

# The full state of a cipher, for comparing two instances byte for byte. The state is private (it's an
# internal cipher detail, not something callers should touch), so the test reaches in for it directly.
# @param rc4 [ED2K::Obfuscation::RC4] The cipher to snapshot.
# @return [Array] Its two indices and permutation.
def rc4_state(rc4)
  [rc4.instance_variable_get(:@i), rc4.instance_variable_get(:@j), rc4.instance_variable_get(:@S)]
end

section 'Extension is loaded'
check(defined?(C_ED2K) && C_ED2K == 1, "the native extension is loaded, so the C variant is available")
check(RC4.new('k', native: true).native == true, "native: true selects the C variant")
check(RC4.new('k', native: false).native == false, "native: false selects the pure Ruby variant")

section 'Known RC4 test vectors'
# Canonical vectors from the RC4 Wikipedia article, checked against both variants.
[
  ['Key',    'Plaintext',      'bbf316e8d940af0ad3'],
  ['Wiki',   'pedia',          '1021bf0420'],
  ['Secret', 'Attack at dawn', '45a01f645fc35b383552544b9bf5']
].each do |key, plain, expected|
  [false, true].each do |native|
    got = RC4.new(key, native: native).encrypt(plain.dup).unpack1('H*')
    check(got == expected, "#{native ? 'C   ' : 'Ruby'} enciphers #{key.inspect} to #{expected} (got #{got})")
  end
end

section 'Output and state parity across random keys and buffers'
# The strongest correctness statement: over many random inputs the two variants must agree exactly,
# both in what they output and in the state they leave behind, before and after enciphering.
srand(1234)
bad_output, bad_state = 0, 0
2000.times do
  key = Array.new(rand(1..64)){ rand(256) }.pack('C*')
  buf = Array.new(rand(0..4096)){ rand(256) }.pack('C*')
  rb, c = RC4.new(key, native: false), RC4.new(key, native: true)
  bad_state  += 1 if rc4_state(rb) != rc4_state(c)   # after the key schedule
  bad_output += 1 if rb.encrypt(buf) != c.encrypt(buf)
  bad_state  += 1 if rc4_state(rb) != rc4_state(c)   # after enciphering
end
check(bad_output.zero?, "2000 random key/buffer pairs produce identical ciphertext (#{bad_output} mismatches)")
check(bad_state.zero?,  "2000 random key/buffer pairs leave identical @i/@j/@S (#{bad_state} mismatches)")

section 'State carries across calls (stream continuity)'
# The cipher is stateful: enciphering a stream in chunks must match enciphering it all at once, which
# only holds if @S/@i/@j survive between calls.
[false, true].each do |native|
  key, data = 'streamkey', 'abcdefghij' * 40
  one  = RC4.new(key, native: native).encrypt(data)
  r    = RC4.new(key, native: native)
  many = data.each_char.each_slice(7).map{ |c| r.encrypt(c.join) }.join
  check(one == many, "#{native ? 'C   ' : 'Ruby'} enciphers in 7-byte chunks the same as in one go")
end

section 'Variants are interchangeable mid-stream'
# Because both keep their state identically, you can even switch implementation partway through a
# stream and land on the same ciphertext as if one variant had done the whole thing.
key, data = 'swapkey', ('x'..'z').to_a.join * 300
ref = RC4.new(key, native: true).encrypt(data)
r = RC4.new(key, native: false)
mixed = +''
data.each_char.each_slice(11).each_with_index do |chunk, n|
  r.instance_variable_set(:@native, n.even?)   # flip implementation every chunk
  mixed << r.encrypt(chunk.join)
end
check(mixed == ref, "alternating Ruby/C every 11 bytes matches a pure C run")

section 'Round trip'
# RC4 is an involution, so a fresh cipher with the same key deciphers what another enciphered.
[false, true].each do |native|
  key, data = 'roundtripkey', 'The quick brown fox' * 20
  ct = RC4.new(key, native: native).encrypt(data)
  pt = RC4.new(key, native: native).decrypt(ct)
  check(ct != data && pt == data, "#{native ? 'C   ' : 'Ruby'} decrypt(encrypt(x)) == x")
end

section 'Edge cases and error handling'
# The native path validates its inputs and its own state rather than reading out of bounds or crashing
# the interpreter, and matches the Ruby path on the awkward key sizes.
r = RC4.new('k'); before = rc4_state(r); r.encrypt!(+'')
check(rc4_state(r) == before, "enciphering an empty buffer is a no-op and leaves state untouched")
check(RC4.new("\x00".b, native: true).encrypt('hello') == RC4.new("\x00".b, native: false).encrypt('hello'),
      "a 1-byte key works and matches Ruby")
k = (0...256).to_a.pack('C*')
check(RC4.new(k, native: true).encrypt('hello') == RC4.new(k, native: false).encrypt('hello'),
      "a 256-byte (maximum) key works and matches Ruby")
check(RC4.new('k').encrypt!(+'hello').encoding == Encoding::BINARY, "encrypt! forces BINARY encoding on its buffer")
s = +'hello'; RC4.new('k').encrypt(s)
check(s == 'hello', "the copying encrypt leaves the original buffer untouched")

def raises(klass)
  yield
  false
rescue klass
  true
end
check(raises(ArgumentError){ RC4.new('') },          "an empty key raises ArgumentError")
check(raises(ArgumentError){ RC4.new('x' * 257) },   "a 257-byte key raises ArgumentError")
check(raises(TypeError){ RC4.new(42) },              "a non-String key raises TypeError")
check(raises(TypeError){ RC4.new('k').encrypt!(42) }, "a non-String buffer raises TypeError")
check(raises(FrozenError){ RC4.new('k').encrypt!('frozen'.freeze) }, "a frozen buffer raises FrozenError")
check(raises(RuntimeError){ r = RC4.new('k'); r.instance_variable_set(:@S, 'too short'); r.encrypt!(+'hi') },
      "a corrupt @S is detected rather than read out of bounds")

if ENV['RC4_BENCH']
  section 'Benchmark (C vs Ruby)'
  key = Digest::MD5.digest('benchmark key')
  # Byte counts are kept modest so the pure Ruby side, at ~2.4 MB/s, still finishes in a minute or so.
  [[16, 200_000], [1024, 30_000], [10 * 1024, 5_000], [1024 * 1024, 100]].each do |size, reps|
    buf = Array.new(size){ rand(256) }.pack('C*')
    note("#{reps} x #{size} bytes (#{'%.1f' % (size * reps / 1024.0 ** 2)} MB total)")
    times = {}
    [false, true].each do |native|
      r = RC4.new(key, native: native)
      GC.start
      times[native] = Benchmark.realtime{ reps.times{ r.encrypt!(buf.dup) } }
      note("  %-4s %7.3f s   %8.2f MB/s   %8.2f us/op" %
        [native ? 'C' : 'Ruby', times[native], size * reps / 1024.0 ** 2 / times[native], times[native] / reps * 1e6])
    end
    check(times[false] > times[true], "  C is faster than Ruby at #{size} bytes (%.1fx)" % (times[false] / times[true]))
  end
else
  note("benchmark skipped; set RC4_BENCH=1 to run it")
end

report
