module ED2K

  # An ED2K [server](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=1267&rm=show_topic) is a node in the
  # ed2k network that serves the purpose of interconnecting users. It doesn't host any files, but it indexes all clients
  # connected to it, as well as all files available and which clients can provide at least part of them, i.e., its sources.
  #
  # Servers are hosts running the [eserver](http://web.archive.org/web/20071012044411/http://lugdunum2k.free.fr/kiten.html)
  # (_edonkey server_) software, which is a free but closed source implementation that handles all the necessary database
  # and networking resources. The latest version, dating from 2006, is [Lugdunum 17.15](https://www.emule-security.org/download.php?view.15),
  # which all main servers implement.
  #
  # There are two ways of communicating with a server:
  #
  # - For stable long-standing connections a TCP stream is used, this is known as _logging in_ the server. In this scenario,
  #   the client will share its files and they will be indexed, and the client will remain as an available source for them
  #   while connected. After logging in, the server will attempt to determine if connections can also be established with
  #   the client, leading to two different scenarios:
  #
  #     * If they can, the [ID assigned](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=103)
  #       to the client will be its IPv4 address. This scenario is known as **High ID** and indicates that other clients can
  #       freely talk to it without having to first route the requests through the server, reducing bandwidth and enabling
  #       communication between users in different servers.
  #
  #     * Otherwise, a random 3-byte ID (below ~16.7M) will be assigned instead, known as a **Low ID**. Since this increases
  #       server bandwidth and reduces communication capabilities between clients, servers normally cap the amount of low
  #       ID users they allow (originally 20% by default, but nowadays often raised to about 80%).
  #
  # - For sporadic short-term requests that don't require a connection UDP messages are used instead. This is the case of
  #   *Global Searches*, for instance, which performs a search query in all servers without necessarily being logged in them.
  #   The eMule extended protocol added several client to client UDP queries added as well, see {Client} for more info.
  #
  # Nothing prevents a client from logging in to multiple servers simultaneously, despite the most well-known software,
  # eMule, imposing that restriction. Indeed, other tools like MLDonkey enable it, and likewise, a {Core} can connect to
  # any amount of servers.
  #
  # Servers have a [limit](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=150) on how many
  # files they will index for each client. Originally this limit was very modest, around 500, but nowadays they are usually
  # at least 1M. The **Soft File Limit** is the amount of files that will be indexed without consequences, while the
  # **Hard File Limit** is the amount that will get a client disconnected if surpassed. It doesn't make sense to share
  # more files than the soft limit, so a {Server} object will always remain within that boundary.
  class Server
    include Connection

    # @param ip [String] The public IPv4 address of the server
    # @param port [Integer] The port the server is listening to for incoming connections
    # @param core [Core] The core object to use when managing this server
    def initialize(ip, port, core: nil)
      @core = core

      # Basic properties we need to establish a connection or send packets
      @ip      = ip
      @port    = port
      @address = Addrinfo.new(Socket.pack_sockaddr_in(@port, @ip))

      # These properties aren't known until we query the server's status and description
      @name        = ''
      @description = ''
      @ping        = -1
      @files       = -1
      @max_users   = -1
      @users       = -1
      @low_id      = -1
      @soft_limit  = -1
      @hard_limit  = -1
      @version     = -1
      @obfuscation = false
    end

  end # Server
end # ED2K
