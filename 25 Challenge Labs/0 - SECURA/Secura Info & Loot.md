Three-machine enterprise environment

## Objectives
- Exploit vulnerabilities in ManageEngine
- Pivot through internal services
- Leverage insecure GPO permissions to escalate privileges
- Compromise the domain

# Domain
- dc01
- secura.yzx

# Hosts

- 192.168.x.95    local.txt
- 192.168.x.96    local.txt, proof.txt
- 192.168.x.97    local.txt, proof.txt

# Users:Passwords
- charlotte : Game2On4.!

- michael                                         <- Likely rabbit hole

- administrator : Almost4There8.?
	- NTLM     :faf613cedb73980bbd34e0a5514df813

- Administrator - 95
	- NTLM     : a51493b0b06e5e35f855245e71af1d14
	- SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
         * Username : apache
         * Domain   : era.secura.local
         * Password : New2Era4.!
	- Winpeas
		- DefaultUserName              :  administrator
		- DefaultPassword               :  Reality2Show4!.?
