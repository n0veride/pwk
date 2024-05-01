

Graphical version of [tcpdump](OS%20Commands.md#tcpdump). Network sniffer used for analyzing network traffic and debugging network services  
  
Uses _Libpcap_ (Linux) and _Winpcap_ (Windows) libraries in order to capture network packets  
  
Capture filters - Will only pass the packets that match the filter criteria to the Capture Engine for processing. All other packets will be dropped.  
  
Network → Capture Filters → Capture Engine → Display Filters