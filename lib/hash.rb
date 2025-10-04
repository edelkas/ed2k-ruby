module ED2K

  # This module encapsulates all the hashing facilities for the different parts of the protocol that require it. Notably,
  # files are identified in the network by a hash computed by MD4-hashing the 9.28MB parts. Furthermore,
  # [AICH](https://www.emule-project.com/home/perl/help.cgi?l=1&rm=show_topic&topic_id=589) (Advanced Intelligent Corruption
  # Handling) provides better granularity by SHA1-hashing the 180KB blocks of one part to recover from corruption.
  # Users are also identified by hashes themselves.
  module Hash

    # Computes the **ed2k hash** of a file, which uniquely identifies the file in the ed2k network. This hash only depends
    # on the contents of the file, not the name nor the metadata. More specifically, the MD4 hash of each 9500KB part is
    # computed, and if there multiple ones, they are concatenated and MD4-hashed again.
    # @note When the file size is an exact multiple of the part size, an extra empty part is appended and hashed. This
    #       was a bug in the initial implementation of eDonkey which was maintained in eMule for backwards compatibility.
    #       Funny enough, the eDonkey client [fixed it](https://web.archive.org/web/20041228095631/http://forum.overnet.com/viewtopic.php?t=57004)
    #       years later in 2004, and other well-known clients like MLDonkey and Shareaza
    #       [followed suit](https://web.archive.org/web/20171110085320/https://mldonkey.sourceforge.net/Ed2k-hash), as did
    #       tools like [ed2k_hash](https://ed2k-tools.sourceforge.net/ed2k_hash.shtml), but eMule never did.
    #       This means that files with those sizes will have different hashes in different clients and thus be
    #       duplicated in the network. **This function implements the "bugged" eMule-compatible version**.
    # @param file [IO] A handle to a readable IO object, normally a file opened in binary mode.
    # @return [String] A 16 bytes (128 bits) binary string with the resulting ed2k hash.
    def hash_file(file)
      hash = ''.b
      parts = file.size / PARTSIZE + 1
      parts.times{ hash << md4(file.read(PARTSIZE).to_s.b) }
      parts == 1 ? hash : md4(hash)
    end
  end
end
