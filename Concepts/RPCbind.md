
**RPCbind** maps RPC services to the ports on which they listen  
  
• RPC processes notify RPCbind when they start, registering the ports they're listening on and the RPC program numbers they expect to serve  
• The client system then contacts RPCbind on the server with a particular RPC program number.  
• The RPCbind service then redirects the client to the proper port number (often TCP/249) so it can communicate with the requested service.  
  
Can use [nmap](Tools.md#nmap) on port 111 to and run the _rcpinfo_ NSE script to find services that may have registered with RPCbind