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
# The protocol specifies both server-client and client-client messages over TCP known as _packets_. UDP is also used for
# some particular queries, specially in the extended protocol, as well as for the Kad network, but a client can still
# function without UDP usage. All packets are little-endian and prefaced by the following 6-byte header:
# ```
# [char]   protocol
# [uint32] size
# [char]   opcode
# ```
# The `protocol` field specifies what family of operations to utilize (*original*, *extended*, *packed*, *kademlia*, *packed kademlia*).
# The `size` field is the length of the payload in bytes, excluding the header itself.
# The `opcode` field specifies what operation is being performed. The same opcode might have different meanings in different protocols.
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
  # ------------ PROTOCOLS
  # The protocol is the first byte of every ed2k packet and specifies the functionality subset to use when handling it.


  OP_EDONKEYPROT        = 0xE3 # Original ed2k protocol
  OP_EMULEPROT          = 0xC5 # Extended eMule protocol
  OP_PACKEDPROT         = 0xD4 # Extended eMule protocol (deflated / gzipped)
  OP_KADEMLIAHEADER     = 0xE4 # Kademlia protocol (serverless)
  OP_KADEMLIAPACKEDPROT = 0xE5 # Kademlia protocol (deflated / gzipped)

  # ------------ CLIENT <-> SERVER TCP OPCODES
  # Original operations of the eDonkey protocol, sent with OP_EDONKEYPROT via TCP.


  # ------------ CLIENT <-> SERVER UDP OPCODES
  # Original operations of the eDonkey protocol, sent with OP_EDONKEYPROT via UDP.


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

  # ------------ SIZES
  # Standard part and block sizes for different purposes


  MAX_EMULE_FILE_SIZE     = 256 * 1024 ** 3 # Supported file size limit (256GB)
  OLD_MAX_EMULE_FILE_SIZE = 4290048000	    # Old file size limit, before 64bit support (~4GB) (((2^32-1)/PARTSIZE)*PARTSIZE = 441 parts)
  PARTSIZE                = 9500 * 1024     # Parts are the primary file subdivision (~9.28MB). Clients can only share completed parts.
  EMBLOCKSIZE             = 180 * 1024      # Blocks are the secondary file subdivision (180KB). Clients usually request these blocks to other clients.
  PACKETSIZE              = 10 * 1024       # Packets are the individual ed2k messages (<10KB). Clients split blocks into this size when sending them.
  PACKET_HEADER_SIZE      = 6               # The header of every ed2k packet contains the protocol (char), size (uint32) and opcode (char).
end

require 'ipaddr'
require 'socket'
require 'thread'

require_relative 'server.rb'
require_relative 'core.rb'
require_relative 'hash.rb'
