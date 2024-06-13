# kygocera (CVE-2022-1026)
Improved Golang Version of Rapid7 PoC for CVE-2022-1026 (https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/)

credits to Aaron Herndon / https://twitter.com/ac3lives

# CVE-2022-1026

### usage:
`git clone https://github.com/r0lh/kygocera.git`
`cd kygocera && go build kygocera.go`
`/kygocera <IP / URL / IP-Range>`
e.g.
`./kygocera 192.168.0.0/24`
`./kygocera printer.mynetwork.local`
`./kygocera 127.0.0.1 -p 9091 -t 200`

or just 
`go run kygocerta 192.168.0.0/24`
