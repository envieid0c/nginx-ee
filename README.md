# Nginx-EE 

Compile and install the latest nginx release with EasyEngine


![nginx-ee](https://raw.githubusercontent.com/VirtuBox/nginx-ee/master/nginx-ee.png)


-----
## Features
* Compile the latest Nginx Mainline or Stable Release 
* Additonal modules
* TLS v1.3 Support

-----

## Additional modules 

Nginx current mainline release : **v1.15.1**  
Nginx current stable release : **v1.14.0**

* [ngx_cache_purge](https://github.com/FRiCKLE/ngx_cache_purge)
* [memcached_nginx_module](https://github.com/openresty/memc-nginx-module)
* [headers-more-nginx-module](https://github.com/openresty/headers-more-nginx-module)
* [ngx_coolkit](https://github.com/FRiCKLE/ngx_coolkit)
* [ngx_brotli](https://github.com/google/ngx_brotli)
* [redis2-nginx-module](https://github.com/openresty/redis2-nginx-module)
* [srcache-nginx-module](https://github.com/openresty/srcache-nginx-module)
* [ngx_http_substitutions_filter_module](https://github.com/yaoweibin/ngx_http_substitutions_filter_module)
* nginx-dynamic-tls-records-patch_1.13.0+
* Openssl 1.1.1
* ngx_http_auth_pam_module
* socks-nginx-module
* lua-nginx-module
* encrypted-session-nginx-module
* iconv-nginx-module
* array-var-nginx-module
* nginx-ts-module
* nginx-rtmp-module
* nginx-module-vts
* graphite-nginx-module
* ngx-fancyindex
* nchan
* rds-json-nginx-module
* nginx-length-hiding-filter-module
* rds-csv-nginx-module
* encrypted-session-nginx-module
* [ipscrub](http://www.ipscrub.org/)
* [virtual-host-traffic-status](https://github.com/vozlt/nginx-module-vts)
* ngx_pagespeed (optional)
* naxsi WAF (optional)
* ModSecurity (optional)
-----

## Compatibility

* Ubuntu 16.04 LTS (Xenial)
* Ubuntu 18.04 LTS (Bionic)
* Debian 8 Jessie

----

## Requirements
* Nginx already installed by EasyEngine 

-----

## Usage

```
bash <(wget -O - https://raw.githubusercontent.com/envieid0c/nginx-ee/master/nginx-build.sh)
```
-----

## Nginx configuration 

* [Wiki](https://github.com/VirtuBox/nginx-ee/wiki/)

-----
## Roadmap
* add nginx configuration examples

Published & maintained by <a href="https://virtubox.net" title="VirtuBox">VirtuBox</a>

## Credits & Licence

* [ipscrub nginx module](http://ipscrub.org/)
