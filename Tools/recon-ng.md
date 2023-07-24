

Module based framework for web-based OSINT. Displays results to terminal and saves to a database which can feed into other modules.  
Can tab-complete.  
Leaving the source option set to default will try to pull from all possibilities w/in the database


**marketplace** - Used to install modules -- Modules w/ * in the ‘K' column displays which modules require credentials or API keys for 3rd party providers  
**search** - Searches for given module  
**info** - Gives info such as path, author, version, last updated, description, dependencies, etc etc.  
**install** - Installs given module  
**modules** **load** - Loads given module  
**info** - Gives details and requirements of loaded module  
**options set** - Sets options of given loaded module (similar to Metasploit)  
**run** - Run module  
**back** - Exit currently loaded module  
**show** - Shows database categories  
**hosts** - Shows hosts discovered (ex: from _recon/domains-hosts/google_site_web_ module)  
  
  
Can import [nmap](nmap.md) (& other tools) to ingest its output into recon-ng's database. Allows you to keep the work done w/in Nmap