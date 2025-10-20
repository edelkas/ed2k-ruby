
### 0.1.0 (21/Oct/2025)

Initial release. Includes:

- ed2k TCP socket implemented, with R/W buffers and packet queues.
- Main classes and modules (e.g. Core, Connection, Server and Client) and some basic constants added.
- Barebones packet parsing and sending, with a few of them implemented, such as:
  - Login to servers.
  - Parse server messages.
- MD4 hashing helper via native C extension for file hashing.