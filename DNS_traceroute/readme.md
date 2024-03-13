The difference between **dns-traceroute** and conventional **traceroute** is that **dns-traceroute** use IP-UDP-DNS packets with incremental TTL, instead of IP-ICMP.

We have two versions: dns-traceroute implemented in Go and the one implemented in Python.

## Go

`go run main.go  --dest=1.1.1.1 --qname=www.baidu.com`

```
listen icmp on any
listen dns on any
Sending package done,Parsing now...
Result:
3   172.18.46.114 (172.18.46.114)  18.241881ms
    172.18.46.82 (172.18.46.82)  8.082107ms
    10.222.172.233 (10.222.172.233)  13.86055ms
4   10.54.57.246 (10.54.57.246)  3.712084ms
5   10.54.159.225 (10.54.159.225)  5.287732ms
    10.54.159.229 (10.54.159.229)  11.121066ms
    198.11.129.50 (198.11.129.50)  16.963298ms
6   116.251.81.113 (116.251.81.113)  6.807844ms
    10.54.58.209 (10.54.58.209)  12.615444ms
    10.54.58.209 (10.54.58.209)  2.450725ms
7   162.158.84.53 (162.158.84.53)  8.276111ms
    172.70.240.3 (172.70.240.3)  14.117541ms
8   172.69.148.3 (172.69.148.3)  5.556383ms
```



## Python

`python3 dns-traceroute.py --dest=1.1.1.1 --qname==www.baidu.com`

```
1     10.41.165.38 115.78798ms
      10.41.163.50 59.53622ms
      10.41.164.34 51.57733ms
2     None 5087.52728ms
      None 5067.47413ms
      None 5075.46377ms
3     10.222.173.17 55.35650ms
      172.18.46.118 47.48988ms
      10.222.173.1 67.51466ms
4     None 5071.50936ms
      11.94.184.214 59.46970ms
      10.54.57.250 59.53288ms
5     10.54.159.225 55.44901ms
      10.54.159.229 67.55018ms
      10.54.57.254 47.57071ms
6     None 5075.52910ms
      116.251.82.65 47.48178ms
      116.251.81.113 59.01313ms
7     172.71.248.3 67.50298ms
      172.69.148.3 59.55195ms
      172.70.240.3 55.51100ms
8     172.71.248.3 63.52353ms
      1.1.1.1 255.56684ms
      1.1.1.1 287.52494ms
```

