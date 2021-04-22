
FROM centos:8

RUN yum install -y make patch gcc pcre-devel openssl-devel zlib-devel wget openssl

WORKDIR /tmp
RUN wget -q https://nginx.org/download/nginx-1.19.8.tar.gz && tar xf nginx-1.19.8.tar.gz
WORKDIR /tmp/nginx-1.19.8
RUN patch -p1 <<< $(wget -qO- https://raw.githubusercontent.com/dedok/nginx-stream-proxy-protocol-v2/main/stream-proxy-protocol-v2-release-1.19.8.patch)

RUN ./configure --with-debug --with-http_ssl_module --with-stream --with-http_auth_request_module --with-stream_ssl_module && \
make && make install

WORKDIR /tmp
RUN openssl req -subj '/CN=localhost/O=/C=SE' -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout server.key -out server.crt
COPY nginx.conf /usr/local/nginx/conf/nginx.conf

EXPOSE 5671
CMD ["/usr/local/nginx/sbin/nginx"]

