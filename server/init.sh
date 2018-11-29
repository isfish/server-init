#! /bin/bash
# Description: Using this Script to install softwares in a new Virtual Peasonal Server(VPS)
# Author: isfish
# Version:  2.1
# Date: 
#	2018-10-23(Created)
#	2018-11-16(Modified, new version)
# Revision: 
#	v1.0 at 2018-10-23: Create the script 
# 	v2.0 at 2018-11-16: Rebulid and rewrite the script
#	v2.1 at 2018-11-29: fix some misspells and logic errors
##########################################################################################

#---------------------Begin the codes-----------------------------------#

# Define and export the system variable
 PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
 export PATH
 
# Define the color of hints
# Waring
 R_E(){
	echo -e "\e[1;31m$1\e[0m"
 }
 # Done
 G_E(){
	echo -e "\e[1;32m$1\e[0m"
 }
 # Hints
 Y_E(){
	echo -e "\e[1;33m$1\e[0m"
 }
 # Working
 B_E(){
	echo -e "\e[1;34m$1\e[0m"
 }
 
# Define the locations
 wk_dir="/usr/src"
 ngx_loc="/usr/local/nginx"
 ac_loc="/usr/local/acme"
 
 # Run this script as root
 if [ $(id -u) != "0" ]; then
	R_E "Sorry, this script must run by root. Please change to root to run this script!"
	exit 1
 fi
 B_E "[+] Install new kernel..."
 # In some old 7.x system, run yum update first to make sure work done correctly.
 yum -y update
 sed -i 's/SELINUX=./SELINUX=dsiabled/g' /etc/selinux/config
 rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
 rpm -Uvh https://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
 yum -y --enablerepo=elrepo-kernel install kernel-ml
 egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
 read -p "Please specify 4.x kernel using number start from 0: " kenNum
 
 # Replace the 3.x kernel with 4.x
 if [ -z ${kenNum} ]; then
	 R_E "Please input choice with a number only!"
 else
 	grub2-set-default ${kenNum}
 fi
 echo 'net.core.default_qdisc=fq'>>/etc/sysctl.conf
 echo 'net.ipv4.tcp_congestion_control=bbr' >>/etc/sysctl.conf
 sysctl -p
 
 # Using the third party yum source to install new and stable softwares.
 B_E "[+] Download softwares..."
 yum install -y epel-release
 yum install -y https://centos7.iuscommunity.org/ius-release.rpm
 yum makecache
 packs="wget curl bzip2 libatomic_ops-devel gcc gcc-c gcc-c++ kmod-nvidia-340xx-340.107-1.el7_5.elrepo.x86_64 git2u python36u python36u-devel python36u-pip patch net-tools lsof vim zlib zlib-devel  pcre pcre-devel zip unzip google-perftools google-perftools-devel GeoIP-devel gd gd-devel"
 for pack in $packs
 	do 
		yum install -y $pack
	done
	
 # Add www to master nginx service
 if grep -Eqi "www" /etc/passwd; then
 	G_E "www has been added."
 else
 	useradd  -s /sbin/nologin www
 fi
 
 # Install and configure nginx
 if [ -s /usr/local/nginx/conf/nginx.conf ]; then
 	G_E "nginx has been installed, nothing to do."
	exit 1
 else
 	cd ${wk_dir}
 	wget http://nginx.org/download/nginx-1.15.6.tar.gz
 	wget https://www.openssl.org/source/openssl-1.1.1.tar.gz
 	tar zxf nginx-1.15.6.tar.gz
 	tar zxf openssl-1.1.1.tar.gz
 	curl https://raw.githubusercontent.com/kn007/patch/43f2d869b209756b442cfbfa861d653d993f16fe/nginx.patch >> nginx.patch
 	curl https://raw.githubusercontent.com/hakasenyang/openssl-patch/master/nginx_strict-sni.patch >> nginx_strict-sni.patch
 	curl https://raw.githubusercontent.com/hakasenyang/openssl-patch/master/openssl-equal-1.1.1_ciphers.patch >> openssl-equal-1.1.1_ciphers.patch
 	curl https://raw.githubusercontent.com/hakasenyang/openssl-patch/master/openssl-1.1.1-chacha_draft.patch >> openssl-1.1.1-chacha_draft.patch
 	git clone https://github.com/wandenberg/nginx-sorted-querystring-module.git
 	git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git
 	git clone https://github.com/eustas/ngx_brotli.git
 	cd ngx_brotli
 	git submodule update --init
 	cd ../openssl-1.1.1
 	patch -p1 < ../openssl-equal-1.1.1_ciphers.patch
 	patch -p1 < ../openssl-1.1.1-chacha_draft.patch
 	cd ../nginx-1.15.6
 	patch -p1 < ../nginx.patch
 	patch -p1 < ../nginx_strict-sni.patch
 	mkdir -p ${ngx_loc}/temp
 	mkdir -p ${ngx_loc}/conf/vhosts
 	./configure \
 	--user=www \
 	--group=www \
 	--http-client-body-temp-path=${ngx_loc}/temp/body \
 	--http-fastcgi-temp-path=${ngx_loc}/temp/fastcgi\
 	--http-proxy-temp-path=${ngx_loc}/temp/proxy \
 	--http-scgi-temp-path=${ngx_loc}/temp/scgi \
 	--http-uwsgi-temp-path=${ngx_loc}/temp/uwsgi \
 	--with-threads \
 	--with-file-aio \
 	--with-pcre-jit \
	--with-libatomic \
 	--with-stream \
	--with-http_ssl_module \
 	--with-stream_ssl_module \
 	--with-stream_realip_module \
 	--with-stream_ssl_preread_module \
 	--with-google_perftools_module \
 	--with-http_slice_module \
 	--with-http_geoip_module \
 	--with-http_v2_module \
 	--with-http_v2_hpack_enc \
 	--with-http_spdy_module \
 	--with-http_sub_module \
	--with-http_dav_module \
 	--with-http_flv_module \
 	--with-http_mp4_module \
 	--with-http_gunzip_module \
	--with-http_geoip_module \
	--with-http_slice_module \
 	--with-http_realip_module \
 	--with-http_addition_module \
 	--with-http_gzip_static_module \
 	--with-http_degradation_module \
 	--with-http_secure_link_module \
 	--with-http_stub_status_module \
 	--with-http_random_index_module \
 	--with-http_auth_request_module \
 	--with-openssl=../openssl-1.1.1 \
 	--add-module=../ngx_brotli \
 	--add-module=../nginx-sorted-querystring-module \
	--with-openssl-opt='enable-tls1_3 enable-weak-ssl-ciphers' \
 	--add-module=../ngx_http_substitutions_filter_module 
 	make
 	make install
 	mv ${ngx_loc}/conf/nginx.conf ${ngx_loc}/conf/nginx_bak
	cat>${ngx_loc}/conf/nginx.conf<<EOF
user  www;
worker_processes  1;
error_log  logs/error.log;
pid        logs/nginx.pid;
events {
	worker_connections  1024;
}		
http {
	include			mime.types;
	default_type		application/octet-stream;
	server_tokens		off;
	charset			UTF-8;
	sendfile		on;
	tcp_nopush		on;
	tcp_nodelay		on;
	keepalive_timeout	60;
	brotli			on;			
	brotli_static 		on;
	brotli_comp_level	6;
	brotli_buffers		32 8k;
	brotli_types		application/javascript application/atom+xml application/rss+xml application/json application/xhtml+xml font/woff font/woff2 image/gif image/jpeg image/png image/svg+xml image/webp image/x-icon image/x-ms-bmp text/css text/x-component text/xml text/plain;
	gzip			on;
	gzip_vary		on;
	gzip_comp_level		6;
	gzip_buffers		16 8k;
	gzip_min_length		1000;
	gzip_proxied		any;
	gzip_disable		"msie6";
	gzip_http_version	1.0;
	gzip_types		text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript image/svg+xml;
	include			vhosts/*.conf;
}
EOF
	cat>${ngx_loc}/conf/vhosts/default.conf<<EOF
server{
		listen          80;
		server_name     localhost;
		root		html;
		index		index.html;
}

EOF
 	${ngx_loc}/sbin/nginx -t
 	if [ $? != "0" ]; then
 		R_E "Failed to install nginx, please check log for details!"
 		exit 1
 	else
 		G_E "Nginx installed successful!"
 		cat>/lib/systemd/system/nginx.service<<EOF
[Unit]
	Description=Nginx Process Manager
	After=network.target
[Service]
	Type=forking
	ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
	ExecReload=/usr/local/nginx/sbin/nginx -s reload
	ExecStop=/usr/local/nginx/sbin/nginx -s quit
	PrivateTmp=false
[Install]
	WantedBy=multi-user.target
EOF
 	fi
 	systemctl enable nginx 
 	systemctl start nginx
 fi
 service firewalld start
 firewall-cmd --zone=public --add-service=http --permanent 
 firewall-cmd --zone=public --add-service=https --permanent
 mkdir -p /home/www/site
 mkdir -p /home/www/ssl
 chown -R www:www /home/www
 
 # install acme.sh to get certificate
 cd ${wk_dir}
 if [ -d ${ac_loc} ]; then
 	G_E "Acme.sh has been installed, nothing to do!"
 else
 	git clone https://github.com/Neilpang/acme.sh.git
 	cd acme.sh
 	./acme.sh --install --home ${ac_loc} --cert-home ${ac_loc}/certs --config-home ${ac_loc}/config
 fi
 	rm -rf /usr/src/ng* /usr/src/op* /usr/src/ac*
	2>&1 | tee -a /root/init.log
 	reboot
	




