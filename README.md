# kygocera (CVE-2022-1026)
Improved Golang Version of Rapid7 PoC for CVE-2022-1026 (https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/)

credits to Aaron Herndon / https://twitter.com/ac3lives

greets to https://github.com/D4RKMATT3R


# CVE-2022-1026

### install
```
git clone https://github.com/r0lh/kygocera.git
cd kygocera && go build kygocera.go
./kygocera -u <IP / URL / IP-Range>
```

or

```
go install github.com/r0lh/kygocera@latest
kygocera -h
```

### usage
```
kygocera -h

kygocera -u 192.168.0.0/24

kygocera -u printer.mynetwork.local
```

set timeout (in milliseconds) and port

```
./kygocera 127.0.0.1 -p 9091 -t 200
```

disable ssl 
```
./kygocera 192.168.0.0/24 -n
```

or just 

```
go run kygocera 192.168.0.0/24
```
