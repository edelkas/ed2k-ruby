# This project is a WIP Ruby implementation of the classic server-based P2P eDonkey protocol, **ed2k**, and the eMule extended
# protocol, used in the [eDonkey network](https://en.wikipedia.org/wiki/EDonkey_network) and implemented by clients such as
# [eDonkey2000](https://web.archive.org/web/20060827140711/http://www.edonkey.com/index.html) (originally),
# [eMule](https://www.emule-project.com/) (predominantly),
# [MLDonkey](https://github.com/ygrek/mldonkey),
# [aMule](https://github.com/amule-project/amule),
# [lPhant](https://web.archive.org/web/20080206023028/http://www.lphant.com/) or
# [Shareaza](https://shareaza.sourceforge.net/), among others.
#
# It is not intended to be a fully fledged ed2k client, but rather a low-level layer that abstracts away the socket management,
# protocol communications, and ed2k network interfacing, by using an event-driven model. A client can then build upon this
# by deciding and implementing how to process each operation in the corresponding handlers at a higher level.
#
# ## Network architecture
#
# The network relies on **servers** to index files, clients, sources, and other metadata; but they don't store any files.
# **Clients** can then connect to them to have their own shared files indexed, perform searches, or query for sources for a
# given file, among other operations. Once clients discover each other through the server, they can then connect to each
# other and share files or other information. The eMule extended protocol also allows clients to exchange sources (other
# known clients).
#
# In order for clients to be able to receive incoming connections from other clients they must have their corresponding
# ports open, in which case they'll be asigned a *High ID* by the server, which will in fact be their IP address. Otherwise
# they're assigned a *Low ID*, and this condition severely harms their networking capabilities. A high ID client can still
# connect to a low ID one _in the same server_ by relaying callback requests through the server, but this incurs in overhead
# and is often limited by servers. Two low ID clients cannot connect to each other at all (it used to be possible to relay
# all data through the server, but this feature was promptly removed for obvious reasons).
#
# Later versions of eMule added the [Kad network](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=232),
# which is an [implementation](https://xlattice.sourceforge.net/components/protocol/kademlia/specs.html) of the
# [Kademlia protocol](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
# that provides an entirely independent serverless method for clients to discover each other and perform searches. It's a
# [DHT](https://en.wikipedia.org/wiki/Distributed_hash_table) (Distributed Hash Table) method, ubiquitous nowadays
# (BitTorrent, IPFS, Ethereum...). This allows the ed2k network to function even without server support, although in
# practice eMule uses both networks concurrently. Support for the Kad network is not planned for now, but might in the future.
#
# A lot of information about the ed2k network, the protocols, and the way clients work, can be found in the fantastic
# resource that is the [eMule Project](https://www.emule-project.com/home/perl/help.cgi?l=1) documentation page.
#
# ## Packet format
#
# The protocol specifies both server-client and client-client messages over TCP known as _packets_. All TCP packets are
# # little-endian and prefaced by the following 6-byte header:
# ```
# [char]   protocol
# [uint32] size
# [char]   opcode
# ```
# The `protocol` field specifies what family of operations to utilize (*original*, *extended*, *packed*, *kademlia*, *packed kademlia*).
# The `size` field is the length of the payload in bytes minus 5 (i.e. excluding the protocol and size fields).
# The `opcode` field specifies what operation is being performed. The same opcode might have different meanings in different protocols.
#
# eMule also makes extensive use of UDP packets, particularly for three purposes: global server queries, the eMule extended
# protocol, and the Kad network. A client can still function without UDP usage though. UDP packet headers lack the size
# field, since it can be inferred from the UDP headers themselves.
#
# Another important aspect of the protocol are **tags**, which are tuples formed by a `type`, a `length` and a `value`. They allow
# to extend the protocol by appending additional information to preexisting opcodes. An unknown tag can simply be skipped by
# an older version of the software.
#
# ## Other aspects
#
# The protocol also informally specifies "netiquette" regards that should be observed in order to prevent being banned
# by servers or other clients, such as query frequency, payload size, etc.
#
# Many of the constants defined here are present in eMule's original [source code](https://github.com/irwir/eMule/blob/master/opcodes.h),
# and in those cases the name is preserved so that it can be looked up in there for reference. Some of the values, however, are changed
# for more reasonable up-to-date ones, and many other hardcoded values (which eMule's source uses _a lot_!) are abstracted
# to new constants instead. Constants referring to deprecated or (yet-)unimplemented features aren't ported.
module ED2K
  DEBUG = false # Produce a debug build (requires additional libs)

  # ------------ PROTOCOLS
  # The protocol is the first byte of every ed2k packet and specifies the functionality subset to use when handling it.


  OP_EDONKEYPROT        = 0xE3 # Original ed2k protocol
  OP_EMULEPROT          = 0xC5 # Extended eMule protocol
  OP_PACKEDPROT         = 0xD4 # Extended eMule protocol (deflated / gzipped)
  OP_KADEMLIAHEADER     = 0xE4 # Kademlia protocol (serverless)
  OP_KADEMLIAPACKEDPROT = 0xE5 # Kademlia protocol (deflated / gzipped)

  # ------------ CLIENT -> SERVER TCP OPCODES
  # Original operations of the eDonkey protocol, sent by the client with OP_EDONKEYPROT via TCP.


  OP_LOGINREQUEST  = 0x01 # Login to the server (see {Server#send_login}).
  OP_GETSERVERLIST = 0x14 # Request server list (see {Server#send_server_list_request}).

  # ------------ SERVER -> CLIENT TCP OPCODES
  # Original operations of the eDonkey protocol, sent by the server with OP_EDONKEYPROT via TCP.


  OP_REJECT        = 0x05 # Our last command was rejected. This can happen e.g. if we send a malformed command or incorrect protocol.
  OP_SERVERLIST    = 0x32 # List of known servers
  OP_SERVERSTATUS  = 0x34 # Current user and file count
  OP_SERVERMESSAGE = 0x38 # Notices sent by the server.
  OP_IDCHANGE      = 0x40 # The ID we've been assigned in this session
  OP_SERVERIDENT   = 0x41 # Information about the server (hash, IP, port, name, description)

  # ------------ CLIENT <-> SERVER UDP OPCODES
  # Original operations of the eDonkey protocol, sent with OP_EDONKEYPROT via UDP.


  OP_GLOBSEARCHREQ3  = 0x90 # Global search with support for large files (>4GB)
  OP_GLOBSEARCHREQ2  = 0x92 # Global search with multiple results per packet
  OP_GLOBSERVSTATREQ = 0x96 # Status request / server ping
  OP_GLOBSERVSTATRES = 0x97 # Status response (user count, file count, file limits, flags, UDP key...)
  OP_GLOBSEARCHREQ   = 0x98 # Global search
  OP_GLOBSEARCHRES   = 0x99 # Global search result
  OP_SERVER_DESC_REQ = 0xA2 # Description request
  OP_SERVER_DESC_RES = 0xA3 # Description response (name, description)

  # ------------ CLIENT <-> CLIENT TCP OPCODES
  # Original operations of the eDonkey protocol, sent with OP_EDONKEYPROT via TCP.


  # ------------ CLIENT <-> CLIENT EXTENDED TCP OPCODES
  # Extended operations of the eMule protocol, sent with OP_EMULEPROT or OP_PACKEDPROT via TCP.


  # ------------ CLIENT <-> CLIENT EXTENDED UDP OPCODES
  # Extended operations of the eMule protocol, sent with OP_EMULEPROT or OP_PACKEDPROT via UDP.


  # ------------ SOCKET
  # Basic configuration of the connection, most of these can be configured


  DEFAULT_TCP_PORT = 4662 # TCP port for incoming ed2k connections
  DEFAULT_UDP_PORT = 4666 # UDP port for incoming ed2k and Kad connections

  # ------------ VERSIONING
  # Used for identifying the version of the eMule client specifically. These values are the last official client ones.


  EDONKEYVERSION = 0x3C # Last version of the original eDonkey2000 client
  VERSION_MJR    =    0 # Major version of eMule
  VERSION_MIN    =   50 # Minor version of eMule
  VERSION_UPDATE =    1 # The update is the letter (1 = a, 2 = b...)
  VERSION_BUILD  =   16 # The build number is purely for debug and unused in practice

  # ------------ SIZES
  # Standard part and block sizes for different purposes


  MAX_EMULE_FILE_SIZE     = 256 * 1024 ** 3 # Supported file size limit (256GB)
  OLD_MAX_EMULE_FILE_SIZE = 4290048000	    # Old file size limit, before 64bit support (~4GB) (((2^32-1)/{PARTSIZE})*{PARTSIZE} = 441 parts)
  PARTSIZE                = 9500 * 1024     # Parts are the primary file subdivision (~9.28MB). Clients can only share completed parts.
  EMBLOCKSIZE             = 180 * 1024      # Blocks are the secondary file subdivision (180KB). Clients usually request these blocks to other clients.
  PACKETSIZE              = 10 * 1024       # Packets are the individual ed2k messages (<10KB). Clients split blocks into this size when sending them.
  PACKET_HEADER_SIZE      = 6               # The header of every ed2k packet contains the protocol (char), size (uint32) and opcode (char).
  UDP_PACKET_HEADER_SIZE  = 2               # UDP packet headers lack the size field (inferred from the datagram), leaving just protocol (char) and opcode (char).

  # ------------ CONNECTION TAGS
  # These are sent when connecting to a server (login) or another client (hello) to exchange information about our client


  CT_NAME          = 0x01 # Nickname
  CT_PORT          = 0x0f # TCP port we're listening to
  CT_VERSION       = 0x11 # eDonkey version (always {EDONKEYVERSION} = 0x3C)
  CT_SERVER_FLAGS  = 0x20 # Bitfield for some capabilities we support
  CT_EMULE_VERSION = 0xfb # eMule version (major, minor and update packed) (eserver 17.3)

  # ------------ SERVER CAPABILITIES
  # Flags sent to the server during login (via CT_SERVER_FLAGS) to communicate the subset of functionalities we support
  # Protocol obfuscation (a.k.a. crypt layer) was added in eMule v0.47b. It "encrypts" packet data to appear random as
  # opposed to the usual predictable structure, but it doesn't provide real privacy, just a layer against simple network filters.


  SRVCAP_ZLIB         = 0x0001 # Support compressed packets via {OP_PACKEDPROT} protocol (eserver 16.40 / eMule0.30b)
  SRVCAP_IP_IN_LOGIN  = 0x0002 # We send our own IP during login (unused)
  SRVCAP_AUXPORT      = 0x0004 # Additional ports for the _server_ to listen to (unused) (eserver 16.45 / eMule0.42e)
  SRVCAP_NEWTAGS      = 0x0008 # Support for Lugdunum new-style tags (see {Tag.write}) (eserver 16.46 / eMule0.42f)
  SRVCAP_UNICODE      = 0x0010 # Support for Unicode strings (eserver 17.1 / eMule0.44a)
  SRVCAP_LARGEFILES   = 0x0100 # Support for 64 bit file sizes (4GB to 256GB) (eserver 17.8 / emule0.47a)
  SRVCAP_SUPPORTCRYPT = 0x0200 # Support for obfuscated connections (eserver 17.13 / eMule0.47b)
  SRVCAP_REQUESTCRYPT = 0x0400 # Request obfuscated connections to servers and clients, but allow fallback to non-obfuscated ones
  SRVCAP_REQUIRECRYPT = 0x0800 # Enforce obfuscated connectons, reject any clients and servers which don't support it, and plaintext connections

  # ------------ SERVER TCP FLAGS
  # These flags are sent by the server to communicate the capabilities they support. They are essentially the same as the
  # above server capabilities, although a slightly different subset of them.


  SRV_TCPFLG_COMPRESSION    = 0x0001 # Supports compressed packets via {OP_PACKEDPROT} protocol (eserver 16.40 / eMule0.30b)
  SRV_TCPFLG_NEWTAGS        = 0x0008 # Supports Lugdunum new-style tags (see {Tag.write}) (eserver 16.46 / eMule0.42f)
  SRV_TCPFLG_UNICODE        = 0x0010 # Supports Unicode strings (eserver 17.1 / eMule0.44a)
  SRV_TCPFLG_RELATEDSEARCH  = 0x0040 # Supports searching for related files (eserver 17.5 / eMule0.46b)
  SRV_TCPFLG_TYPETAGINTEGER = 0x0080 # Supports searching by file type (eserver 17.7)
  SRV_TCPFLG_LARGEFILES     = 0x0100 # Suports 64-bit file sizes (4GB to 256GB) (eserver 17.8 / emule0.47a)
  SRV_TCPFLG_TCPOBFUSCATION = 0x0400 # Supports protocol obfuscation via TCP (eserver 17.13 / eMule0.47b)

  # ------------ SERVER UDP FLAGS
  # Flags sent by the server on the stats request UDP packet, communicates a series of UDP-relevant capabilities
  # related to global searches, UDP obfuscation, etc.


  SRV_UDPFLG_EXT_GETSOURCES  = 0x0001 # Supports multiple files in GetSources packet (eserver 16.40 / eMule0.30d)
  SRV_UDPFLG_EXT_GETFILES    = 0x0002 # Supports multiple search results per packet (eserver 16.40 / eMule0.30d)
  SRV_UDPFLG_NEWTAGS         = 0x0008 # Supports Lugdunum new-style tags (see {Tag.write}) (eserver 16.46 / eMule0.42f)
  SRV_UDPFLG_UNICODE         = 0x0010 # Supports Unicode strings (eserver 17.1 / eMule0.44a)
  SRV_UDPFLG_EXT_GETSOURCES2 = 0x0020 # Supports adding filesize to GetSources packet to avoid mismatches (eserver 17.3 / eMule0.46a)
  SRV_UDPFLG_LARGEFILES      = 0x0100 # Support for 64 bit file sizes (4GB to 256GB) (eserver 17.8 / emule0.47a)
  SRV_UDPFLG_UDPOBFUSCATION  = 0x0200 # Supports protocol obfuscation for UDP communications (eserver 17.13 / eMule0.47b)
  SRV_UDPFLG_TCPOBFUSCATION  = 0x0400 # Supports protocol obfuscation for TCP communications (eserver 17.13 / eMule0.47b)

  # ------------ SERVER TAGS
  # These tags are used to identify different attributes of a server. They're sent in some packets, such as OP_SERVERIDENT,
  # and stored in the server.met file.


  ST_SERVERNAME         = 0x01 # [String] Server name
  ST_DESCRIPTION        = 0x0B # [String] Server description
  ST_PING               = 0x0C # [uint32] Ping in milliseconds
  ST_FAIL               = 0x0D # [uint32] Number of connection errors since last succesfull connection
  ST_PREFERENCE         = 0x0E # [uint32] Connection priority ()
  ST_PORT               = 0x0F # [uint32] Server port (yes, it's sent with a full 4 bytes)
  ST_IP                 = 0x10 # [uint32] Server IPv4 address
  ST_DYNIP              = 0x85 # [String] DNS for servers using dynamic IPs
  ST_MAXUSERS           = 0x87 # [uint32] Maximum amount of users the server supports
  ST_SOFTFILES          = 0x88 # [uint32] Soft file limit, past which further offered files are ignored
  ST_HARDFILES          = 0x89 # [uint32] Hard file limit, past which a user gets kicked from the server
  ST_LASTPING           = 0x90 # [uint32] Last time we pinged the server
  ST_VERSION            = 0x91 # [uint32] Version of eserver being ran (can also be a string), generally 17.15
  ST_UDPFLAGS           = 0x92 # [uint32] Server capabilities packet as a bitfield
  ST_AUXPORTSLIST       = 0x93 # [String] List of additional ports (comma-separated) in case the main one isn't available (unused)
  ST_LOWIDUSERS         = 0x94 # [uint32] Count of connected clients with low ID (unreachable)
  ST_UDPKEY             = 0x95 # [uint32] Used for generating the encryption key during UDP obfuscation
  ST_UDPKEYIP           = 0x96 # [uint32] IP used for getting the UDP key, which must match whenever used
  ST_TCPPORTOBFUSCATION = 0x97 # [uint16] TCP port for obfuscated connections
  ST_UDPPORTOBFUSCATION = 0x98 # [uint16] UDP port for obfuscated connections

  # Convert an IPv4 address string into an integer.
  # @param ip [String] The IP address in its usual representation.
  # @return [Integer] The packed IP
  def self.pack_ip(ip)
    ip.split('.').map(&:to_i).pack('C4').unpack1('L>')
  end

  # Format an IPv4 address into human-readable form.
  # @param ip [Integer] The IP as received from the network
  # @return [String] The formatted IP
  def self.unpack_ip(ip)
    [ip].pack('L>').unpack('C4').map(&:to_s).join('.')
  end

  # Helper to serialize raw binary data for logging purposes
  # @param data [String] Raw data to serialize
  # @return [String] Serialized data
  def self.serialize(data, width = 16)
    data.bytes.lazy.each_slice(width).map{ |bytes|
      bytes.map{ |i| i.to_s(16).rjust(2, '0') }.join(' ')
    }.force.join("\n")
  end
end

require 'digest'
require 'ipaddr'
require 'socket'
require 'stringio'
require 'thread'

if ED2K::DEBUG
  require 'byebug'
end

require_relative 'tags.rb'
require_relative 'throttling.rb'
require_relative 'core.rb'
require_relative 'connection.rb'
require_relative 'server.rb'
require_relative 'client.rb'
require_relative 'hash.rb'
require_relative 'obfuscation.rb'

# The native extension hooks its functions onto the modules and classes above, so it must be loaded last
require_relative 'ced2k'
