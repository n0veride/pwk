
Usage:
```bash
netdiscover [-i device] [-r range | -l file | -p] [-m file] [-F filter] [-s time] [-c count] [-n node] [-dfPLNS]
```

| Option           | Desc                                                                                         |
| ---------------- | -------------------------------------------------------------------------------------------- |
| -i device:       | Your network device                                                                          |
| -r range:        | Scan a given range instead of auto scan. 192.168.6.0\/24,\/16,\/8                            |
| -l file:         | Scan the list of ranges contained into the given file                                        |
| -p passive mode: | Do not send anything, only sniff                                                             |
| -m file:         | Scan a list of known MACs and host names                                                     |
| -F filter:       | Customize pcap filter expression (default: "arp")                                            |
| -s time:         | Time to sleep between each ARP request (milliseconds)                                        |
| -c count:        | Number of times to send each ARP request (for nets with packet loss)                         |
| -n node:         | Last source IP octet used for scanning (from 2 to 253)                                       |
| -d               | Ignore home config files for autoscan and fast mode                                          |
| -f               | Enable fastmode scan, saves a lot of time, recommended for auto                              |
| -P               | Print results in a format suitable for parsing by another program and stop after active scan |
| -L               | Similar to -P but continue listening after the active scan is completed                      |
| -N               | Do not print header. Only valid when -P or -L is enabled.                                    |
| -S               | Enable sleep time suppression between each request (hardcore mode)                           |

If -r, -l, or -p are not enabled, netdiscover will scan for common LAN addresses.
