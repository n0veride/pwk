


```bash
mknod <pipe> p; nc -l -p <port> < <pipe> | nc <ip> <new_port> > <pipe>
```