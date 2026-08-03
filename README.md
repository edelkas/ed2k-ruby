# ed2k-ruby

An ed2k protocol abstraction layer compatible with eMule, made in Ruby.

Heavily in progress, do expect breaking changes!

## Synopsis

This gem is a work-in-progress Ruby implementation of the classic server-based P2P eDonkey protocol, **ed2k**, and the eMule extended protocol, used in the [eDonkey network](https://en.wikipedia.org/wiki/EDonkey_network) and implemented by clients such as [eDonkey2000](https://web.archive.org/web/20060827140711/http://www.edonkey.com/index.html) (originally), [eMule](https://www.emule-project.com/) (predominantly), [MLDonkey](https://github.com/ygrek/mldonkey), [aMule](https://github.com/amule-project/amule), [lPhant](https://web.archive.org/web/20080206023028/http://www.lphant.com/) or [Shareaza](https://shareaza.sourceforge.net/), among others.

It is not intended to be a fully fledged ed2k client, but rather a low-level layer that abstracts away the socket management, protocol communications, and ed2k network interfacing, by using an event-driven model. A client can then build upon this by deciding and implementing how to process each operation in the corresponding handlers at a higher level.

## Installing

If installing it directly simply run:

```gem install ed2k```

Or add this to your **Gemfile** to have it available in your project:

```gem "ed2k"```

The gem comes with a native C extension for the most intensive tasks (e.g. hashing and encryption).

## Usage

The ed2k network is orchestrated by exchanging **ed2k packets**. The basic usage flow of this gem is really simple:

- Create a new `Core` instance and configure it.
- Set up handlers for each type of received packet or other events.
- Spin up the core and start sending packets of your choice.

The gem only abstracts away the protocol details, **you** must decide how to handle each packet when building your client.

### Example 1: Logging in to a server

Let's start simple by creating a trivial client that will only connect to the network, log into a server with High ID, request the list of known servers, wait for the responses, and disconnect.

```ruby
require '../lib/ed2k.rb'

# Our client info
MY_PORT = 4662
MY_HASH = ED2K::Hashing.create_client_hash # reuse later!
MY_NAME = 'rubymule'

# Our current state
core = ED2K::Core.new
id = 0

# Set up event handlers
core.handle_hello do |client, packet|
  client.send_hello(true, MY_HASH, id, name: MY_NAME) if !packet.answer
end

core.handle_id_change do |server, packet|
  id = packet.id
  server.send_server_list_request
end

# Connect and login
return unless core.start(MY_PORT)
server = core.add_server('176.123.5.89', 4725) # eMule Sunrise
core.connect(server)
server.send_login(MY_HASH, MY_NAME)

# Idle
trap('INT'){ core.stop; exit(0) }
sleep
```

- First we initialize some personal information. The port should be able to receive incoming TCP connections (i.e. be "open"). The hash is random, but should be preserved for later as it encodes our credits in the network. You can import this from eMule.
- Initialize the **core** with the default configuration and set up handlers for two events: the `Hello` packet and the `IDChange` packet:
  * `Hello` packets are exchanged when first connecting to a client. After sending a login request to a server, they'll attempt to connect to us as a client to determine if our port is open. We need to reply with a valid `Hello` answer packet.
  * The `IDChange` packet is the response to our login request, if successful. At this point we can exchange more TCP packets if desired; we request the list of known servers.
- **Start** the core, this creates and starts monitoring the sockets, queueing and parsing packets, etc. You're now in the ed2k network.
- Finally, create a new server, connect to it, and send the login request. Then we simply idle, our handlers will take care of the rest. Before exiting you must **stop** the core for proper cleanup.

**Note**: During the usual login sequence other packets are also received from the server: server status, server identification, etc. You can set up handlers for these as well, but in this case they'll simply get logged and discarded.

## Netiquette

The ed2k network informally specifies many restrictions or limitations that should be observed in order to prevent being kicked or banned by servers or other clients, such as query frequency, payload size, etc. In general it suffices to use common sense and avoid spamming requests. I'll try to document them in the relevant methods as much as I can, but it'll be your responsibility to honor them.

## References

- [eMule Project](https://www.emule-project.com/home/perl/help.cgi?l=1).