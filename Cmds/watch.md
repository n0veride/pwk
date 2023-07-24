
Run a designated command at regular intervals (default every 2 seconds)  
  
  
  
**-n** _x_ - Changes default interval to _x_ seconds  
**-e** - Freeze on command error. Exits on key press.  
**-g** - Exit when output of command changes  
**-x** OR **--exec** - Pass command to **exec**(2) instead of **sh -c**. Reduces the need to use extra quoting to get the desired effect.  
**-h** - Display help and exit