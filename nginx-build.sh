#!/bin/bash

# variables

NGINX_STABLE=1.14.0
NGINX_MAINLINE=1.15.0

# Colors
CSI="\\033["
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"

cd /tmp >> /tmp/nginx-ee.log 2>&1
wget http://luajit.org/download/LuaJIT-2.1.0-beta3.tar.gz >> /tmp/nginx-ee.log 2>&1
tar -xzvf LuaJIT-2.1.0-beta3.tar.gz >> /tmp/nginx-ee.log 2>&1
cd LuaJIT-2.1.0-beta3/ >> /tmp/nginx-ee.log 2>&1
make >> /tmp/nginx-ee.log 2>&1
make install >> /tmp/nginx-ee.log 2>&1

export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1/

# Check if user is root
if [ "$(id -u)" != "0" ]; then
    echo "Error: You must be root to run this script, please use the root user to install the software."
    exit 1
fi

clear

# additionals modules choice

echo ""
echo "Welcome to the nginx-ee bash script."
echo ""

echo ""
echo "Do you want to compile the latest Nginx Mainline [1] or Stable [2] Release ?"
while [[ $NGINX_RELEASE != "1" && $NGINX_RELEASE != "2" ]]; do
    read -p "Select an option [1-2]: " NGINX_RELEASE
done

echo ""
echo "Do you want Ngx_Pagespeed ? (y/n)"
while [[ $pagespeed != "y" && $pagespeed != "n" ]]; do
    read -p "Select an option [y/n]: " pagespeed
done

echo ""
echo "Do you want ModSecurity ? (y/n)"
while [[ $modsecurity != "y" && $modsecurity != "n" ]]; do
    read -p "Select an option [y/n]: " modsecurity
done

echo ""
echo "Do you want NAXSI WAF (still experimental)? (y/n)"
while [[ $naxsi != "y" && $naxsi != "n" ]]; do
    read -p "Select an option [y/n]: " naxsi
done
echo ""

# set additionals modules

if   [ "$NGINX_RELEASE" = "1" ]
then
    NGINX_RELEASE=$NGINX_MAINLINE
else 
    NGINX_RELEASE=$NGINX_STABLE
fi


if [ "$naxsi" = "y" ]
then
    ngx_naxsi="--add-module=/usr/local/src/naxsi/naxsi_src "
else
    ngx_naxsi=""
fi

if [ "$pagespeed" = "y" ]
then
    ngx_pagespeed="--add-module=/usr/local/src/incubator-pagespeed-ngx-latest-beta "
else
    ngx_pagespeed=""
fi

if [ "$modsecurity" = "y" ]
then
    ngx_modsecurity="--add-module=/usr/local/src/Modsecurity "
else
    ngx_modsecurity=""
fi

## install prerequisites 

echo -ne "       Installing dependencies               [..]\\r"
apt-get update >> /tmp/nginx-ee.log 2>&1
apt-get install -y git build-essential libtool automake autoconf zlib1g-dev \
libpcre3-dev libgd-dev libssl-dev libxslt1-dev libxml2-dev libgeoip-dev \
libgoogle-perftools-dev libperl-dev libpam0g-dev libxslt1-dev libbsd-dev >> /tmp/nginx-ee.log 2>&1

if [ $? -eq 0 ]; then
	    echo -ne "       Installing dependencies                [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "        Installing dependencies              [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

## clean previous compilation

rm -rf /usr/local/src/* >> /tmp/nginx-ee.log 2>&1
cd /usr/local/src || exit

## get additionals modules

echo -ne "       Downloading additionals modules        [..]\\r"

git clone https://github.com/FRiCKLE/ngx_cache_purge.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/memc-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/simpl/ngx_devel_kit.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/headers-more-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/echo-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/redis2-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/srcache-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/set-misc-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/FRiCKLE/ngx_coolkit.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/sto/ngx_http_auth_pam_module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/envieid0c/socks-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/simplresty/ngx_devel_kit.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/lua-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/encrypted-session-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/calio/iconv-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/array-var-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/arut/nginx-ts-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/sergey-dryabzhinsky/nginx-rtmp-module.git  >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/vozlt/nginx-module-vts.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/mailru/graphite-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/aperezdc/ngx-fancyindex.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/slact/nchan.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/rds-json-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/nulab/nginx-length-hiding-filter-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/rds-csv-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/openresty/encrypted-session-nginx-module.git >> /tmp/nginx-ee.log 2>&1
git clone https://github.com/masonicboom/ipscrub.git ipscrubtmp >> /tmp/nginx-ee.log 2>&1
cp -rf /usr/local/src/ipscrubtmp/ipscrub /usr/local/src/ipscrub >> /tmp/nginx-ee.log 2>&1

wget https://people.freebsd.org/~osa/ngx_http_redis-0.3.8.tar.gz >> /tmp/nginx-ee.log 2>&1
tar -zxf ngx_http_redis-0.3.8.tar.gz >> /tmp/nginx-ee.log 2>&1
mv ngx_http_redis-0.3.8 ngx_http_redis

if [ $? -eq 0 ]; then
	    echo -ne "       Downloading additionals modules        [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "        Downloading additionals modules      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

# get brotli

echo -ne "       Downloading brotli                     [..]\\r"

git clone https://github.com/google/ngx_brotli.git >> /tmp/nginx-ee.log 2>&1
cd ngx_brotli || exit
git submodule update --init --recursive >> /tmp/nginx-ee.log 2>&1

if [ $? -eq 0 ]; then
	    echo -ne "       Downloading brotli                     [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading brotli      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

## get openssl 

echo -ne "       Downloading openssl                    [..]\\r"

cd /usr/local/src || exit

git clone https://github.com/openssl/openssl.git >> /tmp/nginx-ee.log 2>&1
#cd openssl || exit
#git checkout tls1.3-draft-18 >> /tmp/nginx-ee.log 2>&1

cd /usr/local/src || exit

if [ $? -eq 0 ]; then
	    echo -ne "       Downloading openssl                    [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading openssl      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

## get naxsi 

if [ "$naxsi" = "y" ]
then
  echo -ne "       Downloading naxsi                      [..]\\r"
    git clone https://github.com/nbs-system/naxsi.git >> /tmp/nginx-ee.log 2>&1
  cd /usr/local/src || exit
  
  if [ $? -eq 0 ]; then
	    echo -ne "       Downloading naxsi                      [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading naxsi      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
  fi

fi

## get ngx_pagespeed

if [ "$pagespeed" = "y" ]
then
  echo -ne "       Downloading pagespeed               [..]\\r"
    bash <(curl -f -L -sS https://ngxpagespeed.com/install) --ngx-pagespeed-version latest-beta -b /usr/local/src >> /tmp/nginx-ee.log 2>&1
  cd /usr/local/src/ || exit

  if [ $? -eq 0 ]; then
	    echo -ne "       Downloading pagespeed                  [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading pagespeed      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
  fi
fi

## get modsecurity

if [ "$modsecurity" = "y" ]
then
  echo -ne "       Downloading modsecurity                      [..]\\r"
    git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity >> /tmp/nginx-ee.log 2>&1
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git >> /tmp/nginx-ee.log 2>&1
    cd /usr/local/src/ModSecurity ; git submodule init ; git submodule update ; ./build.sh ; ./configure ; make ; make install
    mkdir /etc/nginx/modsec
    wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
    mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
  cd /usr/local/src || exit

  if [ $? -eq 0 ]; then
	    echo -ne "       Downloading modsecurity                      [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading modsecurity      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
  fi

fi

## get nginx

echo -ne "       Downloading nginx                      [..]\\r"
wget http://nginx.org/download/nginx-${NGINX_RELEASE}.tar.gz >> /tmp/nginx-ee.log 2>&1
tar -xzvf nginx-${NGINX_RELEASE}.tar.gz >> /tmp/nginx-ee.log 2>&1
mv nginx-${NGINX_RELEASE} nginx

cd /usr/local/src/nginx/ || exit

if [ $? -eq 0 ]; then
	    echo -ne "       Downloading nginx                      [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "       Downloading nginx      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

## apply dynamic tls records patch

echo -ne "      applying nginx patch                   [..]\\r"

wget https://raw.githubusercontent.com/cujanovic/nginx-dynamic-tls-records-patch/master/nginx__dynamic_tls_records_1.13.0%2B.patch >> /tmp/nginx-ee.log 2>&1
patch -p1 < nginx__dynamic_tls_records_1.13*.patch >> /tmp/nginx-ee.log 2>&1

if [ $? -eq 0 ]; then
	    echo -ne "       applying nginx patch                   [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "        applying nginx patch      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
fi

## configuration

echo -ne "       Configure nginx                       [..]\\r"

./configure \
 $ngx_naxsi \
 --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
 --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
 --prefix=/usr/share/nginx  \
 --conf-path=/etc/nginx/nginx.conf \
 --http-log-path=/var/log/nginx/access.log \
 --error-log-path=/var/log/nginx/error.log \
 --lock-path=/var/lock/nginx.lock \
 --pid-path=/run/nginx.pid \
 --http-client-body-temp-path=/var/lib/nginx/body \
 --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
 --http-proxy-temp-path=/var/lib/nginx/proxy \
 --http-scgi-temp-path=/var/lib/nginx/scgi  \
 --http-uwsgi-temp-path=/var/lib/nginx/uwsgi  \
 --with-pcre-jit  \
 --with-http_ssl_module  \
 --with-http_stub_status_module  \
 --with-http_realip_module  \
 --with-http_auth_request_module  \
 --with-http_addition_module  \
 --with-http_geoip_module  \
 --with-http_perl_module \
 --with-http_gzip_static_module  \
 --with-http_image_filter_module  \
 --with-http_v2_module  \
 --with-http_sub_module  \
 --with-http_xslt_module  \
 --with-file-aio \
 --with-threads  \
 --add-module=/usr/local/src/ngx_cache_purge  \
 --add-module=/usr/local/src/memc-nginx-module \
 --add-module=/usr/local/src/ngx_devel_kit  \
 --add-module=/usr/local/src/headers-more-nginx-module \
 --add-module=/usr/local/src/echo-nginx-module  \
 --add-module=/usr/local/src/ngx_http_substitutions_filter_module  \
 --add-module=/usr/local/src/redis2-nginx-module  \
 --add-module=/usr/local/src/srcache-nginx-module  \
 --add-module=/usr/local/src/set-misc-nginx-module  \
 --add-module=/usr/local/src/ngx_http_redis   \
 --add-module=/usr/local/src/ngx_brotli  \
 --add-module=/usr/local/src/ngx_http_auth_pam_module \
 --add-dynamic-module=/usr/local/src/socks-nginx-module \
 --add-dynamic-module=/usr/local/src/lua-nginx-module \
 --add-dynamic-module=/usr/local/src/encrypted-session-nginx-module \
 --add-dynamic-module=/usr/local/src/iconv-nginx-module \
 --add-dynamic-module=/usr/local/src/array-var-nginx-module \
 --add-dynamic-module=/usr/local/src/nginx-ts-module \
 --add-dynamic-module=/usr/local/src/nginx-rtmp-module \
 --add-dynamic-module=/usr/local/src/nginx-module-vts \
 --add-dynamic-module=/usr/local/src/graphite-nginx-module \
 --add-dynamic-module=/usr/local/src/ngx-fancyindex \
 --add-dynamic-module=/usr/local/src/nchan \
 --add-dynamic-module=/usr/local/src/rds-json-nginx-module \
 --add-dynamic-module=/usr/local/src/nginx-length-hiding-filter-module \
 --add-dynamic-module=/usr/local/src/rds-csv-nginx-module \
 --add-dynamic-module=/usr/local/src/encrypted-session-nginx-module \
 --add-dynamic-module=/usr/local/src/ModSecurity-nginx \
 --add-module=/usr/local/src/ipscrub \
 $ngx_pagespeed \
 --with-openssl=/usr/local/src/openssl \
 --with-openssl-opt=enable-tls1_3 \
 --sbin-path=/usr/sbin/nginx  >> /tmp/nginx-ee.log 2>&1

 if [ $? -eq 0 ]; then
	    echo -ne "       Configure nginx                        [${CGREEN}OK${CEND}]\\r"
	    echo -ne "\\n"
	else
	    echo -e "        Configure nginx      [${CRED}FAIL${CEND}]"
	    echo ""
	    echo "Please look at /tmp/nginx-ee.log"
	    echo ""
	    exit 1
 fi

 ## compilation

 echo -ne "       Compile nginx                          [..]\\r"

make -j "$(nproc)" >> /tmp/nginx-ee.log 2>&1
make install >> /tmp/nginx-ee.log 2>&1

if [ $? -eq 0 ]; then
     echo -ne "       Compile nginx                          [${CGREEN}OK${CEND}]\\r"
     echo -ne "\\n"
   else
     echo -e "        Compile nginx      [${CRED}FAIL${CEND}]"
     echo ""
     echo "Please look at /tmp/nginx-ee.log"
     echo ""
     exit 1
fi

## restart nginx with systemd

systemctl unmask nginx >> /tmp/nginx-ee.log 2>&1
systemctl enable nginx >> /tmp/nginx-ee.log 2>&1
systemctl start nginx >> /tmp/nginx-ee.log 2>&1
nginx -t >> /tmp/nginx-ee.log 2>&1
service nginx reload >> /tmp/nginx-ee.log 2>&1

systemctl restart nginx >> /tmp/nginx-ee.log 2>&1
apt-mark hold nginx-ee nginx-common >> /tmp/nginx-ee.log 2>&1

# We're done !
echo ""
echo -e "       ${CGREEN}Nginx ee was compiled successfully !${CEND}"
echo ""
echo "       Installation log : /tmp/nginx-ee.log"
echo ""