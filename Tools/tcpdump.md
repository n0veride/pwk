


Command line version of [Wireshark](wireshark.md). Network sniffer used for analyzing network traffic and debugging network services  
  
Ability to capture network traffic determined by local user permissions.  
  
  
Can both capture network packets and read from existing capture files  
  
**-A** - Print each packet in ascii. Useful for web pages.  
**-n** - Don't convert addresses (ip, port, etc) to names  
**-r** _file_ - Read from a _file_  
**src host** _ip_ - Filter by source host  
**dst host** _ip_ - Filter by destination host  
**port** _port_ - Filter by port. Requires **-n** switch  
**-X** - Print packet data in both HEX and ASCII  
  
  
[Header](TCP%20-%20Header-Flags.md) **Filtering:**  
  
In order to see only ACK and PSH flags, we need to filter for both the 4th and 5th bit of the 14th byte of the TCP header.  
Turning on only these bits would give us 00011000, or decimal 24, which we can pass as a display filter, hopefully only giving us the HTTP requests and responses data.  

```bash
‘tcp[13] = 24’
```


As a byte array starts w/ 0, we use 13 to specify the 14th byte.  
  
Ex:  
```bash
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

OR  
(NEED TO GET SYNTAX DOWN - KEEPS ERRORING OUT DURING PARSING)  
```bash
sudo tcpdump -A -n 'tcp[tcpflags] & tcp-ack == tcp-ack' -r password_cracking_filtered.pcap
```