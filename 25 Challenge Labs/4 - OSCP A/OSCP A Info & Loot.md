
3 Stand alone machines
- All have `local.txt` and `proof.txt`
3 connected via AD

# IPs

## AD IPs

| IP            | Name | OS  | Flags        |
| ------------- | ---- | --- | ------------ |
| 10.10.x.140   | DC   |     | local, proof |
| 192.168.x.141 | MS01 | Win | local, proof |
| 10.10.x.142   | MS02 |     | local, proof |

## Standalone IPs

| IP            | Name    | OS    | Flags        |
| ------------- | ------- | ----- | ------------ |
| 192.168x.143  | Aero    | Linux | local, proof |
| 192.168.x.144 | Crystal | Linux | local, proof |
| 192.168.x.145 | Hermes  | Win   | local, proof |

# Users

| User   | PW  | Hashes | Found On | Works On |
| ------ | --- | ------ | -------- | -------- |
| offsec | lab |        |          | .250     |
