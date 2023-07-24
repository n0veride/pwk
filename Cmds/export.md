

Define variables within Bash terminal that are accessable to any subprocesses spawned from current Bash instance. Use **$** to reference the variable.  
  
Adding an [environment variable](Env%20Vars.md) without export it will only be available in the current shell.

```bash
export victim_ip=10.11.1.220  
ping -c 4 $victim_ip
```