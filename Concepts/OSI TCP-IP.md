
7: **Application Layer** - Network Process to Application - DNS, WWW, HTTP, SMTP, Telnet, FTP, etc. Exploit User ID/Password, Sniffing  
	• Serves as the window for users and application processes to access the network services  
	• End User layer  
6: **Presentation Layer** - Data Representation and Encryption Phishing, SSL/ TLS Session Sniffing  
	• Formats the data to be presented to the Application layer. Can be viewed as the “Translator” for the network  
	• Syntax layer. Encrypt/ Decrypt if needed. Character code translation, Data conversion/ compression  
5: **Session Layer** - Inter Host Communication, Session Establishment in TCP, SIP, RTP, RPC, etc Hijacking, Telnet & FTP Sniffing  
	• Allows session establishment between processes running on different stations.  
	• Sync & send to ports (logical). Session establishment, maintenance, termination, & support  
	• (Perform secuirty, name recognition, logging, etc)  
4: **Transport Layer** - End to End Connection and Reliability - TCP, UDP, SSL, TLS, etc Reconnaissance/ DOS, TCP Session Sniffing/ Port Sniffing  
	• Ensures that messages are delivered error-free, in sequence, and w/ no losses or dupes  
	• Message segmentation, acknowledgement, traffic control, and Session multiplexing  
3: **Network Layer** - Path Determination and Logical Addressing - IP, ARP, IPsec, ICMP, IGMP, OSPF, etc MITM, IP Port Sniffing  
	• Controls the operations of the subnet, deciding which physical path the data takes  
	• Routing, subnet traffic control, frame fragmentation, ARP, subnet usage accounting  
	• Routers  
2: **Data Link Layer** - Physical Addressing - Ethernet, 802.11, MAC/LLC, VLAN, ATM, FiberChannel Spoofing, MAC/ ARP Sniffing  
	• Provides error-free transfer of data frames from one node to another over the physical layer  
	• Establishes & terminates logical link btw nodes. Media access control  
	• Frame traffic control, sequencing, acknowledgment, delimiting, error checking  
	• Switch, Bridge  
1: **Physical Layer** - Media, Signal, and Binary Transmission - RS232, RJ45, 1000 Base TX, SCL, etc Sniffing  
	• Concerned with the transmission and reception of the unstructured raw bit stream over the physical medium  
	• Data encoding, Physical medium attachment, Transmission technique, Base or Broad band  
	• Hubs

![[net_models.png]]

![[packet_transfer.png]]