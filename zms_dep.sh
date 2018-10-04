#! /bin/bash
# author:bunsx
# date:10/1/2018
# description: see the first serval echo line
# version: 1.0 
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
echo "--------------------------------------------------"
echo "| A scipt for auto install zmirror in centos vps |"
echo "--------------------------------------------------"
## waring
r_e(){
	echo -e "\e[1;31m$1\e[0m"
}
## job done
g_e(){
	echo -e "\e[1;32m$1\e[0m"
}
## hints
y_e(){
	echo -e "\e[1;33m$1\e[0m"
}
## present working
b_e(){
	echo -e "\e[1;34m$1\e[0m"
}

# run this script as root, if not the process will be canceled.
b_e "[-] check for executor of the script"
if [ $(id -u) != "0" ]; then
	r_e Error: You must run the script as root!
	exit 1
fi

#yum install dependency from ius
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum makecache
yum install -y python36u python36u-devel python36u-pip gcc* git2u  net-tools lsof crontabs openssl openssl-devel zlib zlib-devel pcre pcre-devel gd gd-devel vim tar unzip zip 

# add user to manager nginx 
b_e "[-] add user to manage nginx."
	if grep -Eqi "www" /etc/passwd; then
		g_e "www has been added."
	else
		useradd  -s /sbin/nologin www
	fi
if [ -s /usr/local/nginx ]; then
	g_e "nginx has been installed, nothing to do."
        ngx_loc="/usr/local/nginx"

else
	cd /usr/src
	wget http://nginx.org/download/nginx-1.14.0.tar.gz 
	tar -zxf nginx-1.14.0.tar.gz 
	cd nginx-1.14.0
	./configure --user=www --group=www --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --with-http_v2_module --with-http_gzip_static_module --with-http_sub_module --with-stream --with-stream_ssl_module
	make && make install
	cd ..
	ngx_loc="/usr/local/nginx"
	mkdir -p ${ngx_loc}/conf/vhosts
	mv ${ngx_loc}/conf/nginx.conf ${ngx_loc}/conf/nginx_bak
	cat>${ngx_loc}/conf/nginx.conf<<EOF
		user  www;
		worker_processes  1;
		#error_log  logs/error.log;
		#error_log  logs/error.log  notice;
		#error_log  logs/error.log  info;
		pid        logs/nginx.pid;
		events {
    			worker_connections  1024;
		}		

		http {
    			include            mime.types;
    			default_type       application/octet-stream;
    			server_tokens      off;
    			charset            UTF-8;
    			sendfile           on;
    			tcp_nopush         on;
    			tcp_nodelay        on;
    			keepalive_timeout  60;
    			gzip               on;
    			gzip_vary          on;
    			gzip_comp_level    6;
    			gzip_buffers       16 8k;
    			gzip_min_length    1000;
    			gzip_proxied       any;
   			gzip_disable       "msie6";
    			gzip_http_version  1.0;
    			gzip_types         text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript image/svg+xml;
    			include            vhosts/*.conf;
}
EOF
	${ngx_loc}/sbin/nginx -t
	if [ $? -eq 0 ]; then
		g_e "nginx has been installed successfully, you can go to next step!"
	else
		r_e "sorry, nginx has been failed to install, this work will be stoped!"
		exit 1
	fi
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
systemctl enable nginx.service
systemctl start nginx.service

b_e "[-] configure a certificate for the domain"
read -p "please enter a sub-domain to configure ssl certificate for mirror(like a.abc.com)." domain
if [ -s ${ngx_loc}/conf/vhosts/${domain}.conf ]; then
	r_e "The domain exist, exit"
	exit 1
fi
r_e "=========================================================================================================================="
r_e "=== In oreder to run the mirror correctly, you must use https scheme for your domain, hence you need a ssl certificate ==="
r_e "=== Let's encrypt can provide you a free certificate with wildcard support. so I recommend you to issue a certificate  ==="
r_e "=== from there. Thanks to Neilpang's work, we issue a certificate from Let's easily by his tool--acme.sh. Thanks a lot ==="
r_e "=== here I use this tool to issue a certificate for your domain, and I use dns api to do this because it's convenient  ==="
r_e "=== This mode need you to export the api of your dns server in a spical form as an environmet varabile. And the dnsapi ==="
r_e "=== can be found in your dns server, then you should export them in a special form and enter the correspond infomation ==="
r_e "=== we will check whether you do this correctly, if not, the script will stop and quit. But this dosen't mean that you ==="
r_e "=== can not use this script to depoly the mirror, it just means you need to choose 'no' below and issue a certificate. ==="
r_e "=== For how to do, please visit https://github.com/Neilpang/acme.sh/tree/master/dnsapi for details and do it yourself. ==="
r_e "=========================================================================================================================="
read -p "install acme.sh?[y/n]" ins_acm
case "${ins_acm}" in
	[yY][eE][sS]|[yY])
		r_e "please make sure you have read the infomation above already before continue"
		if [ ! -d /usr/local/acme ]; then
			cd /usr/src
			git clone https://github.com/Neilpang/acme.sh.git acme
			cd acme
			./acme.sh --install --home /usr/local/acme --cert-home /usr/local/acme/certs --config-home /usr/local/acme/config
			cd .. && rm -rf acme
		else
			g_e "acme.sh exist"
		fi
		if [ -d /usr/local/acme/certs/${domain} ]; then
			g_e "=========================================================================================="
			g_e "=== The domain you input here has a certificate, it'll will not be issued, but will be ==="
			g_e "=== used as in .conf file of nginx virtual which use to server as mirror's web server. ==="
			g_e "=========================================================================================="
		else
			read -p "enter your dns server(like dns_dp):" dns_server
			read -p "enter the dns api in the some form as you do before(like, DP_Id, DP_Key)" dns_id dns_key
			if [[ "${dns_server}" = "" ||  "${dns_id}" = ""  || "${dns_key}" = ""  ]]; then
				r_e "none of infomation of dns api can leave as blank, please specify them correctly."
				exit 1
			else
				if env | grep -Eqi "$dns_id" && env | grep -Eqi "$dns_key" ; then
						/usr/local/acme/acme.sh --issue  --dns ${dns_server} -d ${domain}
						if [ $? -ne 0 ]; then
							r_e "problem occurs when issue a certicate, exit."
							exit 1
						fi
				else
					r_e "the infomation of dns api you specify was not found in environment varavile "
					exit 1
				fi	
			fi
		fi
	;;
        [nN][oO]|[nN])
		y_e "============================================================================================================"
		y_e "=== You don't choose to install acme.sh, it may mean you have instated it before or has a issue already. ==="
		y_e "=== in order to run the mirror service here, we need you to provide the infomation of certificate below. ==="
		y_e "============================================================================================================"
		read -p "please input the full location of your public key(like /home/www/mypub.pem):" pub_key
		read -p "please input the full location of your private key(like /home/www/mypub.pem):" priv_key
		if [[ "${pub_key}" = "" || "${priv_key}" = "" ]]; then
			r_e "none of the public key or private key can be blank, you must specify both of them!"
			exit 1
		elif [[ ! -s "${pub_key}" && ! -s "${priv_key}" ]]; then
			r_e "the certifcate you specify is not found, please make suere you has enter a right location."
			exit 1
		else
			g_e "ok, this is certificate will be used later."
		fi
	;;
        *)
                r_e "========================================================================================================"
		r_e "=== You don't do any choose or enter wrong choice, I don't know your mean, so script will be stoped. ==="
		r_e "=== It needs a ssl certificate to make the mirror work correctly. Please make a correct chociceabove ==="
                r_e "========================================================================================================"
		exit 1
esac

b_e "[-] mkdir for your website"
	if [ ! -d "/home/www/site/${domain}" ]; then
        	mkdir -p /home/www/site/${domain} 
	else
		g_e "home exist, nothing to do."
	fi
	y_e "=================================================================================================================="
	y_e "=== We are going to install the site you want to install. please specify the site below, you can installed one ==="
	y_e "=== site a time at different location. we are sorry, but this is the limitation of the zmirror project not us. ==="
	y_e "=== we will use site name as the directory name, and it's located under the domain home of home of nginx user. ==="
	y_e "=================================================================================================================="
	
	r_e "======================================================================================================"
        r_e "=== Enter a port number here to listen mirror server called gunicorn, which works in the your vps. ==="
        r_e "=== please do not enter number like 80,443,3306 etc. which is used by other program. If you depoly ==="
	r_e "=== multi mirrors on the vps, please remember to use different port for each mirror. If you do not ==="
	r_e "=== enter a number, script will be stop. Don't forget to allow this port(s) in the firewall rules. ==="
        r_e "======================================================================================================"
        read -p "please enter a port to listen zmirror server:" port
        if [[ "${port}" = "" ]]; then
                r_e "port not specify, exit."
		exit 1
        elif netstat -ltnp | grep -Eqi "$port"; then
		r_e "the port you specify has been used, exit."
		exit 1
	fi
	sites=("archive_org" "dropbox" "duckduckgo" "economist" "facebook" "google_and_zhwikipedia" "instagram" "thepiratebay" "thumblr" "twitter_mobile" "twitter_pc" "youtube" "youtube_mobile")
	y_e "=========================================="
	y_e "plase choose one site from list below"
	y_e "the sites below you can choose to install."
	y_e "1: ${sites[0]}"
	y_e "2: ${sites[1]}"
	y_e "3: ${sites[2]}"
	y_e "4: ${sites[3]}"
	y_e "5: ${sites[4]}"
	y_e "6: ${sites[5]}"
	y_e "7: ${sites[6]}"
	y_e "8: ${sites[7]}"
	y_e "9: ${sites[8]}"
	y_e "10: ${sites[9]}"
	y_e "11: ${sites[10]}"
	y_e "12: ${sites[11]}"
	y_e "=========================================="
	read -p "please enter which mirror you want to install:" site
	case "${site}" in
		1) 
			site=${sites[0]}
		;;
                2) 
			site=${sites[1]}
                ;;
                3) 
			site=${sites[2]}
                ;;
                4) 
			site=${sites[3]}
                ;;
                5) 
			site=${sites[4]}
                ;;
                6) 
			site=${sites[5]}
                ;;
                7) 
			site=${sites[6]}
                ;;
                8) 
			site=${sites[7]}
                ;;
                9) 
			site=${sites[8]}
                ;;
                10) 
			site=${sites[9]}
                ;;
                11) 
			site=${sites[10]}
                ;;
		12) 
			site=${sites[11]}
                ;;
		*)
			r_e "sorry, sorry no mirror you specify, exit!"
			exit 1
	esac
        cd /home/www/site/${domain}
	if [ -d "/home/www/site/${domain}/${site}" ]; then
		r_e "The site you specified has been installed already, nothing to do."
		exit 1
	else
		git clone https://github.com/aploium/zmirror.git ${site}
		cd ${site}
		python3.6 -m pip install virtualenv setuptools==21
		virtualenv -p python3.6 venv
		./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
		./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
		cp more_configs/config_${site}.py config.py
		sed -i "s#my_host_name = '127.0.0.1'#my_host_name = '${domain}'#g" config.py
		sed -i "s#my_host_scheme = 'http://'#my_host_scheme = 'https://'#g" config.py
		cat>/lib/systemd/system/${site}.service<<EOF
			[unit]
			Description= Auto start for mirror ${site}
			After=network.target
			[Service]
			Restart=On-ailure
			WorkingDirectory=/home/www/site/${domain}/${site}
			ExecStart=/home/www/site/${domain}/${site}/venv/bin/gunicorn --log-file zmirror_${site}.log --access-logfile zmirror_access_${site}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
			[Install]
			WantedBy=multi-user.target
EOF
		systemctl enable ${site}.service
		systemctl start ${site}.service
	fi

## intall certificate and configure nginx vitrual conf
if [ -d /usr/local/acme/certs/${domain} ]; then
	mkdir -p /home/www/ssl/${domain}
	/usr/local/acme/acme.sh --install-cert -d ${domain} --fullchain-file /home/www/ssl/${domain}/pubkey.pem --key-file /home/www/ssl/${domain}/privkey.pem --reloadcmd "service nginx force-reload"
	cat>${ngx_loc}/conf/vhosts/${domain}.conf<<EOF
		server{
        		listen          80;
        		server_name     ${domain};
        		rewrite         ^(.*)$ https://\${server_name}\$1 permanent;
		}	
		server{
        		listen          443 ssl;
        		server_name     ${domain};
       			location / {
               			proxy_pass              http://127.0.0.1:${port};
               			proxy_set_header        Host            \$host;
               			proxy_set_header        X-Real-IP       \$remote_addr;
          			proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
        		}
        			access_log     logs/${domain}.log;
        			add_header      Strict-Transport-Security "max-age=15552000;";
        			ssl             on;
        			ssl_certificate /home/www/ssl/${domain}/pubkey.pem;
        			ssl_certificate_key /home/www/ssl/${domain}/privkey.pem;
        			ssl_ciphers     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
        			ssl_prefer_server_ciphers on;
        			ssl_protocols           TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        			ssl_session_cache       shared:SSL:50m;
        			ssl_session_timeout     1d;
		}
EOF
elif [[ "${pub_key}" = "" && "{priv_key}" = "" ]]; then
	cat>${ngx_loc}/conf/vhosts/${domain}.conf<<EOF
		server{
			listen          80;
			server_name     ${domain};
			rewrite         ^(.*)$ https://\${server_name}\$1 permanent;
                }

                server{
                        listen          443 ssl;
                        server_name     ${domain};
                        location / {
                        		proxy_pass              http://127.0.0.1:${port};
                                		proxy_set_header        Host            \$host;
                                		proxy_set_header        X-Real-IP       \$remote_addr;
                                		proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
                        		}	
                                	access_log     logs/${domain}.log;
                                	add_header      Strict-Transport-Security "max-age=15552000;";
                                	ssl             on;
                                	ssl_certificate ${pub_key};
                                	ssl_certificate_key ${priv_key};
                                	ssl_ciphers     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
                                	ssl_prefer_server_ciphers on;
                                	ssl_protocols           TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
   	                            	ssl_session_cache       shared:SSL:50m;
                                	ssl_session_timeout     1d;
                		}
		}
EOF
else
	r_e "sorry, error occur during certificate, altrough the site may be installed correctly. so please check the ssl configuration manually"
fi
chown -R www:www /home/www/site
service nginx reload

