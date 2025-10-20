Gem::Specification.new do |s|
  s.name        = 'ed2k'
  s.version     = '0.1.0'
  s.summary     = 'eMule compatible implementation of the ed2k (eDonkey2000) network protocol'
  s.description = <<-EOT
    This library intends to eventually provide full support of the ed2k protocol and the
    extended eMule protocol. This protocol uses both TCP and UDP sockets for the
    server-client and client-client communication. Kademlia, a serverless protocol
    also supported by eMule, uses UDP and might be added too.

    This gem is not intended to be a fully-fledged client, but rather a lower-level interface to
    abstract away the protocol details and build a client around it. Think of it like
    Net::HTTP as opposed to an actual HTTP server library.
  EOT
  s.authors     = ['edelkas']
  s.files       = Dir['lib/**/*', 'README.md', 'CHANGELOG.md', 'TODO.md', 'docs/**/*', '.yardopts']
  s.homepage    = 'https://github.com/edelkas/ed2k-ruby'
  s.metadata = {
    "homepage_uri"      => 'https://github.com/edelkas/ed2k-ruby',
    "source_code_uri"   => 'https://github.com/edelkas/ed2k-ruby',
    "documentation_uri" => 'https://www.rubydoc.info/gems/ed2k-ruby',
    "changelog_uri"     => 'https://github.com/edelkas/ed2k-ruby/blob/master/CHANGELOG.md'
  }
  s.extra_rdoc_files = Dir['README.md', 'CHANGELOG.md', 'TODO.md', 'docs/**/*']
  s.extensions = ["ext/extconf.rb"]
  s.require_paths = ["lib", "ext"]
end
