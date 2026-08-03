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
