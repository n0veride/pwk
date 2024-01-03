# pwk


```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```

> Listing 1 - The reccommended way to SSH into Module Exercise VMs

The _UserKnownHostsFile=/dev/null_ and _StrictHostKeyChecking=no_ options have been added to prevent the **known-hosts** file on our local Kali machine from being corrupted.