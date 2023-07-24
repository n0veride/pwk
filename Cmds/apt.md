
Advanced Package Tool  
  
Complete package management system that recursively installs, removes, or updates the requested package by recursively satisfying its requirements and dependencies.  
A package is an archive file containing multiple _.deb_ files. **dpkg** will install directly from the _.deb_ file, but miss dependencies whereas **apt** will not.  
  
When updating or installing a program, the system queries the software repositories (_/etc/apt/sources.list_) for the desired package.  
  
**apt-cache search** - Displays all/ given package information stored in the internal cache database/ repository - Keywords given will match via description not its name.  
**autoremove** - Removes packages that were automatically installed to satisfy dependencies for other packages and are now no longer needed  
**-f / --fix-broken** **install** - Fixes missing package dependencies and repairs existing installs  
**--fix-missing** **update** - Ignores missing package dependencies  
**list** - Lists packages  
**--installed** - List all installed packages  
**purge** - Uninstalls package data and its config files  
**remove** - Uninstalls package data, but will leave behind user config files and dependencies  
**--purge** - Also removes config files  
**show** _package_ - Displays information about the package's dependencies, installation size, the package source, etc.  
-**update** - Update the cached list of available packages, including information related to their versions, descriptions, etc.  
-**upgrade** - Upgrade installed packages (or given packages) and core systems to the latest versions  
  
If there's an "...invalic... not yet valid for x time" error, try:
```bash
sudo apt -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false update
```