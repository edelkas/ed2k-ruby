module ED2K
  # Serialization and parsing of ed2k tags. A tag is an extension of the ed2k protocol allowing to add more data to packets
  # without breaking backwards compatibility, as unknown tags can simply be ignored by clients, since the tag's length
  # is always known.
  #
  # A tag is a triplet formed by a type, an identifier or "name", and the actual value. Not all types are actually used,
  # such as booleans or "bsobs", whatever those are. Here, the type is derived automatically from the supplied value.
  # The tag name can actually be either an integer or a string. Variable-length values are prefixed with its length
  # (2 bytes for strings, 4 bytes for blobs). The tag name is also prefixed by its length (2 bytes).
  #
  # Lugdunum servers added more compact new-style tags which omit the length field. These can be detected by testing the
  # highest bit of the type, which is normally unused. For short string tags, even the string length can be encoded
  # in the type byte, further reducing the tag size by 4 bytes total. New-style tag names must be integers, not strings.
  # The uint8 and uint16 types are only used with new-style tags. New-style are never really sent by eMule, only for
  # storing in files, but they might be received from the server, mainly from search results, which have many tags.
  module Tag

    TAGTYPE_HASH      = 0x01 # [Unused]
    TAGTYPE_STRING    = 0x02 #   Variable length
    TAGTYPE_UINT32    = 0x03 #   4 bytes
    TAGTYPE_FLOAT32   = 0x04 #   4 bytes
    TAGTYPE_BOOL      = 0x05 # [Unused]
    TAGTYPE_BOOLARRAY = 0x06 # [Unused]
    TAGTYPE_BLOB      = 0x07 #   Variable length (eMule 0.44a+)
    TAGTYPE_UINT16    = 0x08 #   2 bytes
    TAGTYPE_UINT8     = 0x09 #   1 byte
    TAGTYPE_BSOB      = 0x0A # [Unused]
    TAGTYPE_UINT64    = 0x0B #   8 bytes

    # Serialize and dump a tag.
    # @param name [Integer,String] The tag "name", which identifies the tag. It can be an integer opcode, or a string name.
    # @param value [Integer,Float,String] The payload of the tag, its type depends on the tag (`Integer` for integer tags, etc).
    # @return [String] The resulting serialized tag as a binary string.
    # @raise [StandardError] If the supplied value has incorrect type.
    def self.write(name, value, new = false)
      # Tag key
      if name.is_a?(Integer)
        key = new ? name.chr : [1, name].pack('S<C') # Length field is always 1
      else
        key = [name.bytesize, name].pack('S<a*')
      end
      switch = new ? 0x80 : 0x00 # Toggle type's highest bit to indicate new-style tag

      # Dump tag triplet (type, key, value)
      case value
      when Integer
        if value <= 0xFF && new
          [TAGTYPE_UINT8 | switch, key, value].pack('Ca*C')
        elsif value <= 0xFFFF && new
          [TAGTYPE_UINT16 | switch, key, value].pack('Ca*S<')
        elsif value <= 0xFFFFFFFF
          [TAGTYPE_UINT32 | switch, key, value].pack('Ca*L<')
        else
          [TAGTYPE_UINT64 | switch, key, value].pack('Ca*Q<')
        end
      when String
        length = value.bytesize
        if value.encoding == Encoding::BINARY
          [TAGTYPE_BLOB | switch, key, length, value].pack('Ca*L<a*')
        elsif length <= 16 && new
          [16 + length | switch, key, value].pack('Ca*a*')
        else
          [TAGTYPE_STRING | switch, key, length, value].pack('Ca*S<a*')
        end
      when Float
        [TAGTYPE_FLOAT32 | switch, key, value].pack('Ca*e')
      else
        raise "Invalid tag value type"
      end
    end

    # Parse a taglist. A taglist is prefixed by the tag count.
    # @note Unknown tag types (bool, bool array, bsob) are consumed but rejected.
    # @param data [String] The raw binary data to unpack the tags from.
    # @param core [Core,nil] The core to log unsupported tag types to, if any. Optional, since tag parsing itself doesn't
    #        need a core, and callers that don't have one at hand can simply omit it.
    # @return [Hash] A hash mapping tag names to the corresponding values. Tag names can be integers or strings.
    def self.read(data, core: nil)
      stream = StringIO.new(data)
      count = stream.read(4).unpack1('L<')
      count.times.map{
        # Parse type and name (old-style vs new-style tags)
        type = stream.read(1).unpack1('C')
        if type >> 7 & 1 == 1 # Highest bit set => New-style tag
          type &= 0x7F
          name = stream.read(1).unpack1('C')
        else
          length = stream.read(2).unpack1('S<')
          name = stream.read(length)
          name = name.ord if length == 1
        end

        # Parse value
        case type
        when TAGTYPE_UINT8
          value = stream.read(1).unpack1('C')
        when TAGTYPE_UINT16
          value = stream.read(2).unpack1('S<')
        when TAGTYPE_UINT32
          value = stream.read(4).unpack1('L<')
        when TAGTYPE_UINT64
          value = stream.read(8).unpack1('Q<')
        when TAGTYPE_FLOAT32
          value = stream.read(4).unpack1('e')
        when TAGTYPE_STRING
          size = stream.read(2).unpack1('S<')
          value = stream.read(size).force_encoding('UTF-8')
        when TAGTYPE_BLOB
          size = stream.read(4).unpack1('L<') # Was a uint16 prior to 0.42e
          value = stream.read(size).b
        when TAGTYPE_HASH
          value = stream.read(16).b
        when TAGTYPE_BOOL      # Ignore
          stream.seek(1, IO::SEEK_CUR)
          next
        when TAGTYPE_BOOLARRAY # Ignore
          size = stream.read(2).unpack1('S<')
          stream.seek(size / 8 + 1, IO::SEEK_CUR)
          next
        when TAGTYPE_BSOB      # Ignore
          size = stream.read(1).unpack1('C')
          stream.seek(size, IO::SEEK_CUR)
          next
        when 0x11..0x20
          value = stream.read(type - 16).force_encoding('UTF-8')
        else
          core&.log_debug("Received unsupported tag type %#.2x" % type)
          next
        end

        # Map names to values in a hash
        [name, value]
      }.compact.to_h
    rescue
      nil
    end

  end
end
