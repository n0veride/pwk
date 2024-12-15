An industrial company building driving systems for the timber industry.
The target got attacked a few weeks ago and now wants to get an assessment of their IT security.

## Objectives
- Find out if an attacker can breach the perimeter
- Get Domain Admin privileges in the internal network.


# IPs

## External IPs

| IP            | Name     | OS    | Flags            |
| ------------- | -------- | ----- | ---------------- |
| 192.168.x.189 | .        | Win   | proof            |
| 192.168.x.191 | Login    | Win   | proof            |
| 192.168.x.245 | WEB01    | Linux | local, proof     |
| 192.168.x.246 | Demo     | Linux | local, proof     |
| 192.168.x.247 | WEB02    | Win   | ~~local, proof~~ |
| 192.168.x.248 | External | Win   | local, proof     |
| 192.168.x.249 | Legacy   | Win   | local, proof     |
| 192.168.x.250 | WINPREP  |       | 0                |

## Internal IPs

| IP         | Name | OS  | Flags        |
| ---------- | ---- | --- | ------------ |
| 172.16x.6  | .    |     | proof        |
| 172.16x.7  | .    |     | local, proof |
| 172.16x.14 | .    |     | local, proof |
| 172.16x.15 | .    |     | local, proof |
| 172.16x.19 | .    |     | local, proof |
| 172.16x.20 | .    |     | local, proof |
| 172.16x.21 | .    |     | proof        |
| 172.16x.30 | .    |     | proof        |

# Users

| User    | PW                   | Hashes                           | Found On | Works On |
| ------- | -------------------- | -------------------------------- | -------- | -------- |
| offsec  | lab                  |                                  | .250     |          |
| zachary |                      | 54abdf854d8c0653b1be3458454e4a3b | .247     |          |
| emma    |                      |                                  |          |          |
| mark    | OathDeeplyReprieve91 | dcbbff66580202a5cbede9c010281ce9 | .247     | .248     |
