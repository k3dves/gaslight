# GASLIGHT
## A extensible HTTPS/HTTP proxy written in golang  
---

### Features:
* Acts as a transparent L7 proxy for HTTP/HTTPS traffic.
* Ability to log all the HTTP traffic and with support for HHTPS traffic passthough using CONNECT method.
* Can decrypt HTTPS traffic between client and a particular host.
* Easily extensible using plugins. Plugins can be used for simply logging all the traffic to a file, forward it to another host, or modifying the traffic between the client and server on-the-fly.

### Prerequisite
* For decryption of HTTPS traffic you need to provide the host cerficiate (forged) wich is trusted by the client. One way to achieve that is by adding our custom CA to the client trust store and generating self-signed certificate for that host.
* If you don't have a valid certificate or you don't want to decrypt the HTTPS traffic, the proxy can be configure to run in transparent mode.