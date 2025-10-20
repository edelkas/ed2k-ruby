Roadmap:

- Finish implementing the essential TCP packets for the ed2k protocol. This would already enable to use the network,
  albeit at a significant disadvantage compared to clients like eMule.
- Add support for the extended eMule protocol packets. This enables many additional measures, such as source exchange
  between clients, protocol obfuscation, secure identification, etc.
- Implement UDP socket and the corresponding packets. Again, a client can work without the UDP packets, but they improve
  the network by providing a way to query servers you aren't logged into (such as global searches), reasking for files
  and retrieving queue positions, etc.
- Add Kad (Kademlia) support. This is much trickier from a technical standpoint compared to the basic ed2k packet structure,
  so we'll see about it!