

IPv4:
![[tcp4_header.png]]

TCP Flags are defined starting from the 14th byte  
  
**CWR** - 1st bit. Used by the sending host to indicate it received a packet with the ECE flag set. 

**ECE** - 2nd bit. Used to indicate if the TCP peer is ECN capable. 

**URG** - 3rd bit. Used to notify the receiver to process the urgent packets before processing all other packets. The receiver will be notified when all known urgent data has been received.  

**ACK** - 4th bit. Used to acknowledge  

**PSH** - 5th bit. Used to enforce immediate delivery of a packet and is commonly used in interactive Application Layer protocols to avoid buffering  

**RST** - 6th bit. Sent from the receiver to the sender when a packet is sent to a particular host that was not expecting it.  

**SYN** - 7th bit. Used as a first step in establishing a three-way handshake between two hosts. Only the first packet from both the sender and receiver should have this flag set.

**FIN** - 8th bit. Used in the last packet sent from the sender signalling there is no more data from the sender.