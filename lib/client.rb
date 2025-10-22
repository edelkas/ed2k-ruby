module ED2K
  # Clients are the nodes in the ed2k network that actually host the files and share them betweem each other. They are
  # hosts running client programs such as
  # [eDonkey2000](https://web.archive.org/web/20060827140711/http://www.edonkey.com/index.html),
  # [eMule](https://www.emule-project.com/),
  # [MLDonkey](https://github.com/ygrek/mldonkey),
  # [aMule](https://github.com/amule-project/amule),
  # [lPhant](https://web.archive.org/web/20080206023028/http://www.lphant.com/) or
  # [Shareaza](https://shareaza.sourceforge.net/), among others.
  # eMule extended the original protocol in many ways, particularly in client-to-client communication. Clients compatible
  # with the eMule extended protocol are known as **eMule compatible**.
  #
  # Clients connect to one or more servers in order to publish the files they are sharing, and the server will
  # index both the clients and the files to interconnect them and provide search functionalities, among others.
  # See {Server} for more info on servers.
  #
  # In order for a client to establish a connection with another client the receiver must be reachable, i.e., have the ports
  # open and a socket listening on them. In this scenario the server will assign you a **High ID** which will be your IPv4
  # address, otherwise you'll be assigned a **Low ID** (a random 3-byte integer). A low ID client can connect to a high ID
  # client, and a high ID client can connect to a low ID client *in the same server* thanks to a callback mechanism that is
  # routed through the server. Two low ID clients cannot connect to each other.
  #
  # Apart from sharing files, clients can exchange a wide variety of messages between themselves, specially in the
  # eMule extended protocol. A notable example is [Source Exchange](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=137&rm=show_topic),
  # which enables a client to query other clients for additional sources for a given file being downloaded. Another
  # example is the ability to query for one's [Queue Ranking](https://www.emule-project.com/home/perl/help.cgi?l=1&topic_id=102&rm=show_topic),
  # i.e., the position of our client in another client's upload queue. The extended protocol also introduced UDP requests
  # between clients for periodic queries, such as file reasks. Note that frequent queries like this can result in
  # getting [blacklisted](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=136).
  class Client
    include Connection

    # The ID of the client is an integer that identifies the client within a server. If it's 4 bytes then it corresponds
    # to its IPv4 address, and this should indicate that the client is reachable and we can establish a connection
    # directly. If it's at most 3 bytes then it's a random identifier assigned by the server, and we can only connect
    # to them by requesting a callback through the server.
    attr_reader :id

    # @param id [Integer] The ID of the client (see {#id})
    # @param port [Integer] The port the client is listening to.
    # @param socket [Socket] The socket, if we're already connected to the client.
    # @param core [Core] The core object to use when managing this client
    def initialize(id: nil, port: nil, socket: nil, core: nil)
      @core = core
      @id   = id
      @hash = nil

      # Connection properties
      @socket = socket
      if @socket
        addr = @socket.remote_address
        @ip      = addr.ip_address
        @port    = addr.ip_port
        @address = Addrinfo.new(Socket.pack_sockaddr_in(@port, @ip))
      else
        @port = port
      end

      # Other properties
      @name     = ''
      @software = ''
      @version  = -1 # eMule-compatible only
      @server   = nil

      # Capabilities
      @supports_obfuscation  = false
      @supports_secure_ident = false
    end

    # Format the client's name in human-readable form
    # @return [String] `ID@IP:Port 'Name'`
    def format_name
      ip = @address ? "%s:%d" % [@address.ip_address, @address.ip_port] : '?'
      name = @name || '?'
      "#{@id}@#{ip} '#{name}'"
    end
  end
end
