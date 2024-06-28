

`127.0.0.1` is normally the IP address assigned to the "loopback" or local-only interface. This is a "fake" network adapter that can only communicate within the same host. It's often used when you want a network-capable application to only serve clients on the same host. A process that is listening on `127.0.0.1` for connections will only receive local connections on that socket.

`0.0.0.0` has a couple of different meanings, but in this context, when a server is told to listen on `0.0.0.0` that means "listen on every available network interface". The loopback adapter with IP address `127.0.0.1` from the perspective of the server process looks just like any other network adapter on the machine, so a server told to listen on `0.0.0.0` will accept connections on that interface too.

Note that, in a different context (routing) `0.0.0.0` usually means the default route (the route to "the rest of" the internet, aside from routes in your local network etc.).