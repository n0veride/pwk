

OpenSSL is a cryptography toolkit implementing the Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) network protocols and related cryptography standards required by them.  
  
For using the various cryptography functions of OpenSSL's crypto library from the shell. It can be used for  
	o Creation and management of private keys, public keys and parameters  
	o Public key cryptographic operations  
	o Creation of X.509 certificates, CSRs and CRLs  
	o Calculation of Message Digests  
	o Encryption and Decryption with Ciphers  
	o SSL/TLS Client and Server Tests  
	o Handling of S/MIME signed or encrypted mail  
	o Time Stamp requests, generation and verification  
  
  
**req** - Initiate new cert signing request  
-**newkey** - Generate a new private key  
**rsa:2048** - Use RSA encryption w/ 2048-bit key length  
**-nodes** - Store private key w/o passphrase protection  
**-keyout** - Save key to a file  
**-x509** - Output self-signed cert instead of a cert request  
**-days** - Set validity period in days  
**-out** - Save cert to a file