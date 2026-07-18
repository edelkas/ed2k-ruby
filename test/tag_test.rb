# Serialization and parsing of ed2k tags ({ED2K::Tag}).

require_relative 'helper.rb'

# Round-trip a list of [name, value] pairs through the serializer and the parser. A taglist is
# prefixed by its count, which Tag::write doesn't emit (it writes one tag at a time), so we add it.
# @param pairs [Array<Array>] The tags to serialize.
# @param new [Boolean] Whether to use compact Lugdunum new-style tags.
# @return [Hash] The parsed tags.
def roundtrip(pairs, new: false)
  body = pairs.map{ |name, value| ED2K::Tag::write(name, value, new) }.join
  ED2K::Tag::read([pairs.size].pack('L<') + body)
end

section 'Module shape'
check(defined?(ED2K::Tag) == 'constant', "ED2K::Tag exists")
check(ED2K::Tag.respond_to?(:write), "Tag::write is a module function")
check(ED2K::Tag.respond_to?(:read), "Tag::read is a module function")
check(ED2K::Tag.const_defined?(:TAGTYPE_STRING, false), "the TAGTYPE_* constants live in Tag")
check(ED2K::Tag::TAGTYPE_FLOAT32 == 0x04, "Tag::TAGTYPE_FLOAT32 holds its usual value")

section 'Round trip, one tag at a time'
got = roundtrip([[ED2K::CT_NAME, 'tester']])
check(got == { ED2K::CT_NAME => 'tester' }, "string tag (got #{got.inspect})")

got = roundtrip([[ED2K::CT_VERSION, 60]])
check(got == { ED2K::CT_VERSION => 60 }, "uint32 tag (got #{got.inspect})")

got = roundtrip([[ED2K::CT_VERSION, 0xFFFFFFFFFF]])
check(got == { ED2K::CT_VERSION => 0xFFFFFFFFFF }, "uint64 tag (got #{got.inspect})")

got = roundtrip([['stringname', 'value']])
check(got == { 'stringname' => 'value' }, "string-named tag (got #{got.inspect})")

blob = "\xDE\xAD\xBE\xEF".b
got = roundtrip([[ED2K::CT_NAME, blob]])
check(got == { ED2K::CT_NAME => blob }, "binary blob tag (got #{got.inspect})")

got = roundtrip([[ED2K::CT_NAME, 'short'], [ED2K::CT_VERSION, 5]], new: true)
check(got == { ED2K::CT_NAME => 'short', ED2K::CT_VERSION => 5 }, "new-style tags (got #{got.inspect})")

section 'Float tags'
# These are single precision (4 bytes). Writing them as doubles used to both lose the value and
# desync the stream for every tag that followed, so all three aspects are checked.
got = roundtrip([[ED2K::CT_NAME, 3.5]])
check(got == { ED2K::CT_NAME => 3.5 }, "exactly representable float round-trips (got #{got.inspect})")

# 3.5 survives either precision, so use a value that doesn't: the rounding error is the fingerprint
# of a genuine 4-byte float, and proves we aren't accidentally agreeing on doubles at both ends.
got = roundtrip([[ED2K::CT_NAME, 0.1]])
value = got[ED2K::CT_NAME]
check(value && (value - 0.1).abs < 1e-7 && value != 0.1,
      "non-exact float round-trips with single-precision error (got #{value.inspect})")
check(ED2K::Tag::write(ED2K::CT_NAME, 3.5).bytesize == 8, "a float tag is 8 bytes total (4 header + 4 value)")

got = roundtrip([[ED2K::CT_NAME, 3.5], [ED2K::CT_VERSION, 60], [ED2K::CT_SERVER_FLAGS, 8]])
check(got == { ED2K::CT_NAME => 3.5, ED2K::CT_VERSION => 60, ED2K::CT_SERVER_FLAGS => 8 },
      "tags following a float still parse, i.e. no stream desync (got #{got.inspect})")

section 'Several tags at once'
got = roundtrip([[ED2K::CT_NAME, 'tester'], [ED2K::CT_VERSION, 60], [ED2K::CT_SERVER_FLAGS, 0x0008]])
check(got == { ED2K::CT_NAME => 'tester', ED2K::CT_VERSION => 60, ED2K::CT_SERVER_FLAGS => 8 },
      "a mixed taglist round-trips (got #{got.inspect})")

section 'Parser robustness'
check(ED2K::Tag::read("\x00" * 2).nil?, "truncated data returns nil rather than raising")
check(ED2K::Tag::read([0].pack('L<')) == {}, "an empty taglist parses to an empty hash")
check(ED2K::Tag::read([1].pack('L<') + ED2K::Tag::write(1, 7)) == { 1 => 7 }, "the core argument is optional")
check(ED2K::Tag::write(1, 1).is_a?(String), "writing doesn't need a core either")

begin
  ED2K::Tag::write(ED2K::CT_NAME, [1, 2, 3])
  check(false, "writing an unsupported value type raises")
rescue StandardError
  check(true, "writing an unsupported value type raises")
end

section 'Login packet build'
# send_login is the main consumer of Tag::write. It used to raise NoMethodError, because write_tag
# was an instance method of module ED2K and nothing ever included it.
with_core do |core|
  server = ED2K::Server.new('1.2.3.4', 4661, core: core)
  server.tcp_setup
  begin
    server.send_login("\x00" * 16, 'tester')
    check(true, "send_login completes without raising")
    check(!server.instance_variable_get(:@control_queue).empty?, "a login packet is queued for sending")
  rescue StandardError => e
    check(false, "send_login completes without raising (got #{e.class}: #{e.message})")
  end
end

report
