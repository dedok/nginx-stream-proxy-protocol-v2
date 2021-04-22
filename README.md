# NGINX.Stream / Proxy Protocol v2

The patch for NGINX.Streams which brings support of proxy protocol v2.
For getting information about configuration please see `Configuration`.

The implementataion is based on `2.2.Binary header format (version 2)` from the
document [1].

Also if you need to extend the proxy protocol reading please see this project [2].

```
[1] http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
[2] https://github.com/slact/nginx_proxy_protocol_tlv_vars
```

# Current status

1. It tested only on Linux, Mac (OSX).
This patch would not work compile under Windows platform, because codes are using some GCC attributes.
3. I'm happy to get any feedback about TLV features. Please create a ticket, if you wish to see more TLV features.

## Current TLVs features:
1. SSL: version, cert conn, cipher, key alg, sig alg.

# Plans

The plan is: I would like to add this patch to the official NGINX.Stream in the future.
Please see this ticket for getting more details: https://trac.nginx.org/nginx/ticket/1639

# Configuration

**syntax:** *proxy_protocol on|off|v2*

1. on and off working as described in the official documentataion [1]
2. v2 sets sending proxy protocol v2 line to the backend.

```
[1] http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_protocol
```

# How to build
1. Choose the version of the NGINX (ex: stream-proxy-protocol-v2-release-1.19.8.patch)
2. Apply the patch:

```bash
$> cd NGINX-SOURCES-ROOT
$> patch -p1 < stream-proxy-protocol-v2-release-1.19.8.patch
# Compile NGINX
```
# Docker
WARNING:
nginx would be built for debug purposes and with debug options,
be careful do not use this image's settings for the production.
1. Change upstreams in the nginx.conf file
2. Execute:
```bash
$> docker build -t nginx-proxy-protocol-v2 .
$> docker run -i -t nginx-proxy-protocol-v2 bash
```

