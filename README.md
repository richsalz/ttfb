# ttfb

This is `ttfb` designed to measure time to first byte in OpenSSL. In other words, a client
sends a small request, and the server responds and the program measure the time between those
two.

Case is being taken to make this as low-overhead as possible, so that almost all the
work is done by OpenSSL.

MIT license.
