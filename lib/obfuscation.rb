module ED2K

  # Implements eMule's **protocol obfuscation**. This feature was introduced in late 2006 in eMule 0.47b and supported
  # by eserver 17.8 onwards. It's purpose is to mask eMule's traffic, originally to prevent being recognized and throttled
  # / blocked by ISPs or network admins, because the raw protocol has a very predictable structure. Nowadays it's probably
  # pointless, but necessary to maintain backwards compatibility, as official clients use it by default.
  #
  # Protocol obfuscation works by ciphering traffic between peers using a symmetric key based RC4 scheme. The keys are
  # negotiated during a handskake (for TCP traffic) or inferred from packet headers (for UDP traffic). All protocols
  # support obfuscation (ed2k, packed ed2k, Kad...), the only exception is Kad UDP packets.
  #
  # Communications between both servers and clients can be obfuscated. They advertise their obfuscation capabilities in
  # certain packets by setting the appropriate flags (see e.g. {SRVCAP_SUPPORTCRYPT}, {SRV_TCPFLG_TCPOBFUSCATION} or
  # {SRV_UDPFLG_UDPOBFUSCATION}).
  #
  # It should be noted that protocol obfuscation is not cryptographically secure, nor does it provide actual privacy.
  # It simply serves as a protection layer against basic network filters, but an attacker properly sniffing the traffic
  # could decipher it.
  #
  # ## References
  # - Official docs: [eMule Project](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=848).
  # - TCP implementation details: [EncryptedStreamSocket.cpp](https://github.com/SomeSupport/eMule/blob/master/EncryptedStreamSocket.cpp).
  # - UDP implementation details: [EncryptedDatagramSocket.cpp](https://github.com/SomeSupport/eMule/blob/master/EncryptedDatagramSocket.cpp).
  # - RC4 cipher details: [Wikipedia](https://en.wikipedia.org/wiki/RC4).
  # - RC4 pseudo-code: [Rivest-Schuldt paper](https://people.csail.mit.edu/rivest/pubs/RS14.pdf).
  #
  # @todo Only supports server <-> client UDP obfuscation for now.
  module Obfuscation extend self

    # Size in bytes of random padding added to obfuscated **UDP** packet headers, can be 0-15 (4 bits).
    # eMule uses no padding, but supports receiving it.
    CRYPT_HEADER_PADDING        = 0

    # Overhead per obfuscated **Kad UDP** packet (usually 16 bytes, see {CRYPT_HEADER_PADDING}).
    CRYPT_HEADER_KAD            = 16 + CRYPT_HEADER_PADDING

    # Overhead per obfuscated **ed2k UDP** packet (usually 8 bytes, see {CRYPT_HEADER_PADDING}).
    CRYPT_HEADER_SIZE           = CRYPT_HEADER_KAD - 8

    # Minimum overhead per obfuscated **UDP** packet, assuming no padding (see {CRYPT_HEADER_PADDING})
    CRYPT_HEADER_WITHOUTPADDING = CRYPT_HEADER_SIZE - CRYPT_HEADER_PADDING

    # Used to generate RC4 keys for **UDP** packets from servers to clients.
    MAGICVALUE_UDP_SERVERCLIENT = 0xA5

    # Used to generate RC4 keys for **UDP** packets from clients to servers.
    MAGICVALUE_UDP_CLIENTSERVER = 0x6B

    # Used to generate RC4 keys for **UDP** packets between two clients.
    MAGICVALUE_UDP              = 91

    # Used in obfuscated **UDP** packets between two clients to verify a packet was correctly deciphered.
    MAGICVALUE_UDP_SYNC_CLIENT  = 0x395F2EC1

    # Used in obfuscated **UDP** packets between a client and a server to verify a packet was correctly deciphered.
    MAGICVALUE_UDP_SYNC_SERVER  = 0x13EF24D5

    # A pure Ruby implementation of the RC4 symmetric cipher. See [Wikipedia](https://en.wikipedia.org/wiki/RC4) and
    # [Rivest-Schuldt paper](https://people.csail.mit.edu/rivest/pubs/RS14.pdf) for pseudo-code and other details.
    # Since RC4 is XOR-based, it's an _involution_, i.e. an encrypted string is decrypted by running the same algorithm
    # with the same key on the output. In other words, {encrypt} and {decrypt} are aliases, and so are {encrypt!} and
    # {decrypt!}.
    # @note An RC4 encoder / decoder object **preserves its state** between runs, so each successive run isn't identical.
    #       This is the usual stream-oriented implementation. Thus, in order to decrypt a previously encrypted stream,
    #       a separate RC4 object with the same key must be created.
    # @todo Add a C++-based version in our native extension for performance, compare both and ensure they match,
    #       benchmark them, and finally let the user choose which version they'd want, defaulting to the native one.
    class RC4

      # @param key [String] An arbitrary binary string to use as key. Can be between 1 and 256 bytes, usually between
      #                     5 and 16, corresponding to key lengths between 40 and 128 bits (the latter for eMule).
      def initialize(key)
        @i, @j = -1, 0
        @S = (0...256).to_a
        key_length = key.length
        while (@i += 1) < 256
          @j = (@j + @S[@i] + key.getbyte(@i % key_length)) % 256
          @S[@i], @S[@j] = @S[@j], @S[@i]
        end
        @i, @j = 0, 0
      end

      # Encrypt an arbitrary string, mutates it in-place and encodes it as binary.
      # @param buffer [String] The data to encrypt.
      # @return [String] The encrypted data, same length as `buffer`.
      def encrypt!(buffer)
        buffer.force_encoding(Encoding::BINARY)
        n = -1
        while (n += 1) < buffer.bytesize
          @i = (@i + 1) % 256
          @j = (@j + @S[@i]) % 256
          @S[@i], @S[@j] = @S[@j], @S[@i]
          buffer.setbyte(n, buffer.getbyte(n) ^ @S[(@S[@i] + @S[@j]) % 256])
        end
        buffer
      end

      # Encrypt an arbitrary string.
      # @param buffer [String] The data to encrypt.
      # @return [String] The encrypted data, same length as `buffer`.
      def encrypt(buffer)
        encrypt!(buffer.dup)
      end

      alias_method :decrypt!, :encrypt!
      alias_method :decrypt, :encrypt
    end

    # Build the suitable RC4 key used for (de-)obfuscating traffic. A different key scheme is used depending on the
    # channel (TCP vs UDP), protocol (ed2k vs Kad) and peers involved (client2client, server2client, client2server).
    # @param random [Integer] A uint32 used to distinguish packets. For outgoing packets our client generates it, for
    #                         incoming packets we receive it in the clear in the packet header.
    # @param incoming [Boolean] Whether this key is for an incoming or an outgoing packet.
    # @param key [String] For server UDP packets, the server UDP key (uint32).
    # @return [String] A 16-byte (128-bit) binary string containing the key, which is always an MD5 hash.
    def build_key(random, incoming, key: nil)
      return unless key
      magic = incoming ? MAGICVALUE_UDP_SERVERCLIENT : MAGICVALUE_UDP_CLIENTSERVER
      seed = [key, magic, random].pack('L<CS<')
      Digest::MD5.digest(seed)
    end

    # Obfuscate a packet in place (see {encrypt}).
    # @param packet [String] An arbitrary binary string to encrypt.
    # @param key [String] For server UDP packets, the server UDP key (uint32).
    # @return [Boolean] Whether the packet was obfuscated or not.
    # @todo Do a single prepend for performance.
    # @todo Support arbitrary (non-zero) padding.
    def encrypt!(packet, key: nil)
      return false unless key()
      random = rand(1 << 16)
      key = build_key(random, false, key: key)
      rc4 = RC4.new(key)
      protocol = OP_EDONKEYPROT
      protocol = rand(256) while protocol == OP_EDONKEYPROT
      packet.prepend([MAGICVALUE_UDP_SYNC_SERVER, 0].pack('L<C'))
      rc4.encrypt!(packet)
      packet.prepend([protocol, random].pack('CS<'))
      true
    end

    # Deobfuscate a packet in place (see {decrypt}).
    # @param packet [String] A binary string containing an encrypted packet to decrypt.
    # @param key [String] For server UDP packets, the server UDP key (uint32).
    # @return [Boolean,nil] `true` if the packet was decrypted, `false` if it wasn't because the packet wasn't encrypted,
    #                       and `nil` if it failed to decrypt.
    # @note Even though the RC4 scheme is symmetric, the entire obfuscation process isn't (e.g. different magic values).
    #       Therefore, {encrypt} and {decrypt} aren't interchangeable.
    # @todo Remove slicing for performance.
    def decrypt!(packet, key: nil)
      return false if packet.size < 8 || !key() # crypt header doesn't fit
      protocol, random = packet.unpack('CS<')
      return false if protocol == OP_EDONKEYPROT # unencrypted
      key = build_key(random, true, key: key)
      rc4 = RC4.new(key)
      packet.slice!(0, 3)
      rc4.decrypt!(packet)
      magic, pad_len = packet.unpack('L<C')
      return if magic != MAGICVALUE_UDP_SYNC_SERVER # invalid magic number
      pad_len &= 0xF
      return if packet.size <= 5 + pad_len # padding doesn't fit
      packet.slice!(0, 5 + pad_len)
      true
    end

    # Obfuscate a packet (see {encrypt!}).
    # @param packet [String] An arbitrary binary string to encrypt.
    # @param key [String] For server UDP packets, the server UDP key (uint32).
    # @return [String,nil] The encrypted packet as a new binary string, or `nil` if encryption failed.
    def encrypt(packet, key: nil)
      new_packet = packet.dup
      encrypt!(new_packet, key: key) ? new_packet : nil
    end

    # Deobfuscate a packet (see {decrypt!}).
    # @param packet [String] A binary string containing an encrypted packet to decrypt.
    # @param key [String] For server UDP packets, the server UDP key (uint32).
    # @return [String,nil] The decrypted packet as a new binary string, or `nil` if decryption failed. If a non-encrypted
    #                      packet is passed in `packet`, it's recognized and left as-is.
    # @note (see #decrypt!)
    def decrypt(packet, key: nil)
      new_packet = packet.dup
      !decrypt!(new_packet, key: key).nil? ? new_packet : nil
    end
  end
end
