# Usage and Testing

> ./proxy 8080 proxyCertificates/proxy_ca.crt proxyCertificates/proxy_ca.key
>
> curl -s -I -x 10.4.2.18:8080 --cacert proxy_ca.crt https://www.google.com | grep -i '^X-Proxy'
