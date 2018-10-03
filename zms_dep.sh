#! /bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# run this script as root, if not the process will be canceled.

if [ $(id -u) != "0" ]; then
	echo "Error: You must run the script as root!"
	exit 1
fi

# yum install dependency from ius
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum makecache
yum install -y python36u python36u-devel python36u-pip gcc* git2u  crontabs openssl openssl-devel zlib zlib-devel pcre pcre-devel gd gd-devel vim tar unzip zip 

echo "add user to manage nginx."
read -p "please enter an user to manager nginx process:" ngx_user
if [[ "${ngx_user}" != "" ]]; then
	if grep -Eqi "${ngx_user}" /etc/passwd; then
		echo "${ngx_user} has been added."
	else
		useradd  -s /sbin/nologin ${ngx_user}
	fi
else
	echo "you must enter user to manager nginx, or the program will be canceled."
	exit 1
fi
if [ -s /usr/local/nginx ]; then
	echo "nginx has been installed, nothing to do."
else
	cd /usr/src
	wget http://nginx.org/download/nginx-1.14.0.tar.gz 
	tar -zxf nginx-1.14.0.tar.gz 
	cd nginx-1.14.0
	./configure --user=${ngx_user} --group=${ngx_user} --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --with-http_v2_module --with-http_gzip_static_module --with-http_sub_module --with-stream --with-stream_ssl_module
	make && make install
	cd ..
	ngx_loc="/usr/local/nginx"
	mv ${ngx_loc}/conf/nginx.conf ${ngx_loc}/conf/nginx_bak
	cat>${ngx_loc}/conf/nginx.conf<<EOF
		user  ${ngx_user};
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
		echo "nginx has been installed successfully, you can go to next step!"
	else
		echo "sorry, nginx has been failed to install, this work will be stoped!"
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
if [ ! -d ${ngx_loc}/conf/vhosts ]; then
	mkdir -p ${ngx_loc}/conf/vhosts
fi
systemctl enable nginx.service
systemctl start nginx.service

echo "====================================================================================================="
echo "do you want to install acme.sh for issue a certificate from Let's encrypt? Default choice is not."
echo "in order to run mirror correctly you must has a certificate for the domain you used as a proxy domain"
echo "if you don't have a certificate yet, please choose 'y' in below"
echo "we will guide you to issue a certificate in a simple way"
echo "====================================================================================================="
read -p "install acme.sh?[y/n]" ins_acm
case "${ins_acme}" in
	[yY][eE][sS])
		cd /usr/src
		git clone https://github.com/Neilpang/acme.sh.git acme 
		cd acme
		read -p "please enter the location you want to install for acme.sh:" ac_home
		read -p "please enter the configuration location for acme.sh:" cfg_home
		read -p "please enter the certshome for store issued certs:" cts_home
		if [[ "${ac_home}"="" || "${cfg_home}"="" ||  "${cts_home}"="" ]]; then
			./acme.sh --install --home /usr/local/acme --cert-home /usr/local/acme/certs --config-home /usr/local/acme/config
		else
			./acme.sh --install --home ${ac_home} --cert-home ${cts_home} --config-home ${cfg_home}
		fi
		read -p "Enter the domain you want to issue a certificate:" domain
			if [[ -s /usr/local/acme/certs/${domain} ]]; then
				echo "=================================================================================="
				echo "the domain you input has a certificate, it'll will not be issued!"
				echo "if the certificate has been expired, please renew it manually after this process!!"
				echo "=================================================================================="
			else
				echo "========================================================================================================================"
				echo "we used dns method to issue a certificate,it means you need to provide your api of your dns server where your domain in."
				echo "you MUST the infomation here, or you will fail to issue a certificate and get error messages."
				echo "please see https://github.com/Neilpang/acme.sh/tree/master/dnsapi for details"
				echo "========================================================================================================================="
				read -p "enter your dns server:" dns_server
					if [[ "${dns_server}" = "" ]]; then 
						echo "you don't specify your dns server, it can not issue a certificate for your domain."
						exit 1
					fi
				if [[ "${ac_home}" != "" && "${ac_home}" != "/usr/local/acme" ]]; then
					${ac_home}/acme.sh --issue --dns ${dns_server} -d ${domain}
				else
					/usr/local/acme/acme.sh --issue --dns ${dns_server} -d ${domain}
				fi
			fi
		if [[ /usr/local/acme/certs/${domain} ]]; then
			mkdir -p /home/${ngx_user}/ssl/${domain}
			/usr/local/acme/acme.sh --install-cert -d ${domain} --fullchain-file /home/${ngx_user}/ssl/${domain}/pubkey.pem --key-file /home/${ngx_user}/ssl/${domain}/privkey.pem --reloadcmd "service nginx force-reload"
			cat>${ngx_loc}/conf/vhosts/${domain}.conf<<EOF
			server{
        			listen          80;
        			server_name     ${domain};
        			rewrite         ^(.*)$ https://\${server_name}\$1' permanent;
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
        				ssl_certificate /home/${ngx_user}/ssl/${domain}/pubkey.pem;
        				ssl_certificate_key /home/${ngx_user}/ssl/${domain}/privkey.pem;
        				ssl_ciphers     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
        				ssl_prefer_server_ciphers on;
        				ssl_protocols           TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        				ssl_session_cache       shared:SSL:50m;
        				ssl_session_timeout     1d;
			}
EOF
		fi
	;;
	[nN][oO])
		echo "===================================================================================================="
		echo "you don't choose to install acme.sh, it may mean you have instated it before or has a issue already."
		echo "we don't care which situation you are in, we need you to provide the infomation below."
		echo "===================================================================================================="
		read -p "please input the location of your public key:" pub_key
		read -p "please input the location of your private key:" priv_key
		if [[ "${pub_key}" ="" || "${priv_key}" ="" ]]; then
			echo "none of the public key or private key can be blank, you must specify both of them!"
			exit 1
		else
			cat>${ngx_loc}/conf/vhosts/${domain}.conf<<EOF
                	server{
                        	listen          80;
                        	server_name     ${domain};
                        	rewrite         ^(.*)$ https://\${server_name}\$1' permanent;
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
EOF
		fi
	;;
	*)
		echo "========================================================================"
		echo "the default is not to installed, please make sure yo have a certificate."
		echo "========================================================================"
		ins_acm="n"
esac
## mkdir for your website 
	mkdir -p /home/${ngx_user}/site/${domain} && cd /home/${ngx_user}/site/${domain}
	echo "============================================================================================================="
	echo "we are going to install the site you want to install."
	echo "please specify the site below, you can installed one site each time at different location."
	echo "we are sorry, but this is the limitation of the zmirror project not us."
	echo "we will use the site name as the directory name, and it's located under the domain home of home ofnginx user."
	echo "============================================================================================================="
	
	echo "=========================================="
	echo "plase choose one site from list below"
	echo "the sites below you can choose to install."
	echo "default site is google and zhwikipedia"
	echo "0: archive"
	echo "1: dropbox"
	echo "2: duduckgo"
	echo "3: economist"
	echo "4: facebook"
	echo "5: googel and zhwikipedia"
	echo "6: instagram"
	echo "7: thepiratebay"
	echo "8: thumblr"
	echo "9: twitter moblie"
	echo "10: twitter pc"
	echo "11: youtube"
	echo "12: youtube mobile"
	echo "=========================================="
	sites={'archive_org' 'dropbox' 'duckduckgo' 'economist' 'facebook' 'google_and_zhwikiepdia' 'instagram' 'thepiratebay' 'thumblr' 'twitter_mobile' 'twitter_pc' 'youtube' 'youtube_mobile'}
	read -p "please enter which mirror you want to install:" site
	case "${site}" in
		0)
			git clone https://github.com/aploium/zmirror.git ${site[0]}
		  	cd ${site}
			python3.6 -m pip install virtualenv setuptools==21
			virtualenv -p python3.6 venv
			./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
			./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
			cp more_configs/config_${site[0]}.py config.py
			
			
	esac 
	git clone https://github.com/aploium/zmirror.git ${site}
	cd ${site}
	python3.6 -m pip install virtualenv
	python3.6 -m pip install setuptools==21
	virtualenv -p python3.6 venv
	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
	cp more_configs/config_google_and_zhwikipedia.py config.py
	sed -i "s#my_host_name ='127.0.0.1'#my_host_name = '${domain}'#g" config.py
	sed -i "s#my_host_scheme='http://'#my_host_scheme='https://'#g" config.py 
	# 启动 zmirror 服务器
	read -p "enter a port for zmirror server to listen" port
	if [[ "${port}" = "" ]]; then
		port="8964"
	fi
	./venv/bin/gunicorn --daemon --capture-output --log-file zmirror.log --access-logfile zmirror-access.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
	service nginx restart
else
	echo "it's failed to issue a certificate."
	exit 
fi

