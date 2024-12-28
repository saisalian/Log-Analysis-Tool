# Incident Report
This report summarizes suspicious activities detected in logs.

## Suspicious Apache Logs
| ip          | datetime                   | method   | url     |   status |   size |
|:------------|:---------------------------|:---------|:--------|---------:|-------:|
| 10.0.0.5    | 04/Dec/2024:10:35:10 +0000 | POST     | /login  |      403 |    564 |
| 192.168.1.2 | 04/Dec/2024:11:00:00 +0000 | GET      | /admin  |      500 |    789 |
| 172.16.0.1  | 04/Dec/2024:11:15:42 +0000 | DELETE   | /config |      200 |    100 |
| 172.16.0.2  | 04/Dec/2024:11:20:10 +0000 | PUT      | /backup |      403 |     50 |

## Suspicious JSON Logs
| timestamp            | ip          |   status | message                    | level   |
|:---------------------|:------------|---------:|:---------------------------|:--------|
| 2024-12-04T10:35:10Z | 10.0.0.5    |      403 | POST /login                | ERROR   |
| 2024-12-04T11:00:00Z | 192.168.1.2 |      500 | Failed to fetch admin data | ERROR   |

