#! /bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
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

if [ $(id -u) != "0" ]; then
	r_e Error: You must run the script as root!
	exit 1
fi

# yum install dependency from ius
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum makecache
yum install -y python36u python36u-devel python36u-pip gcc* git2u  crontabs openssl openssl-devel zlib zlib-devel pcre pcre-devel gd gd-devel vim tar unzip zip 
# add user to manager nginx 
b_e "[-] add user to manage nginx."
read -p  "please enter an user to manager nginx process:" ngx_user
if [[ "${ngx_user}" != "" ]]; then
	if grep -Eqi "${ngx_user}" /etc/passwd; then
		g_e "${ngx_user} has been added."
	else
		useradd  -s /sbin/nologin ${ngx_user}
	fi
else
	r_e "you must enter user to manager nginx, or the program will be canceled."
	exit 1
fi
if [ -s /usr/local/nginx ]; then
	g_e "nginx has been installed, nothing to do."
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
if [ ! -d ${ngx_loc}/conf/vhosts ]; then
	mkdir -p ${ngx_loc}/conf/vhosts
fi
systemctl enable nginx.service
systemctl start nginx.service

y_e "====================================================================================================="
y_e "do you want to install acme.sh for issue a certificate from Let's encrypt? Default choice is not."
y_e "in order to run mirror correctly you must has a certificate for the domain you used as a proxy domain"
y_e "if you don't have a certificate yet, please choose 'y' in below"
y_e "we will guide you to issue a certificate in a simple way"
y_e "====================================================================================================="
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
				y_e "=================================================================================="
				y_e "the domain you input has a certificate, it'll will not be issued!"
				y_e "if the certificate has been expired, please renew it manually after this process!!"
				y_e "=================================================================================="
			else
				y_e "========================================================================================================================"
				y_e "we used dns method to issue a certificate,it means you need to provide your api of your dns server where your domain in."
				y_e "you MUST the infomation here, or you will fail to issue a certificate and get error messages."
				y_e "please see https://github.com/Neilpang/acme.sh/tree/master/dnsapi for details"
				y_e "========================================================================================================================="
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
		else
			r_e "sorry, it's failed to issue a certificate. please make sure you have enter the right dns api and dns server already."
		fi
	;;
	[nN][oO])
		y_e "===================================================================================================="
		y_e "you don't choose to install acme.sh, it may mean you have instated it before or has a issue already."
		y_e "we don't care which situation you are in, we need you to provide the infomation below."
		y_e "===================================================================================================="
		read -p "please input the location of your public key:" pub_key
		read -p "please input the location of your private key:" priv_key
		if [[ "${pub_key}" ="" || "${priv_key}" ="" ]]; then
			r_e "none of the public key or private key can be blank, you must specify both of them!"
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
		y_e "========================================================================"
		y_e "the default is not to installed, please make sure yo have a certificate."
		y_e "========================================================================"
		ins_acm="n"
	;;
esac
b_e "[-] mkdir for your website"
	if [ ! -d "/home/${ngx_user}/site/${domain}" ]; then
        	mkdir -p /home/${ngx_user}/site/${domain} && cd /home/${ngx_user}/site/${domain}
	else
		g_e "home exist, nothing to do."
	fi
	y_e "=============================================================================================================="
	y_e "we are going to install the site you want to install."
	y_e "please specify the site below, you can installed one site each time at different location."
	y_e "we are sorry, but this is the limitation of the zmirror project not us."
	y_e "we will use the site name as the directory name, and it's located under the domain home of home of nginx user."
	y_e "=============================================================================================================="
	
	y_e "================================================================================================="
        y_e "enter a port number here to listen zmirror server called gunicorn, this is work behind server."
        y_e "please do not enter number like 80,443,3306,21 etc. which is used by other program."
        y_e "we recommend you to enter a number higher than 4000, and remember this port is not used by others"
        y_e "if you depoly multi mirrors on the same vps, be caution not to use a confilct number."
        y_e "if you don't enter a number. 8964 will be used as default. However, it's not a good idea"
        y_e "besides don't forget to put this port into firewall rules(i.e. iptables, firewalld)"
        y_e "=================================================================================================="
        read -p "please enter a port to listen zmirror server:" port
        if [[ "${port}" = "" ]]; then
                port="8964"
        fi

	y_e "=========================================="
	y_e "plase choose one site from list below"
	y_e "the sites below you can choose to install."
	y_e "default site is google and zhwikipedia"
	y_e "0: archive"
	y_e "1: dropbox"
	y_e "2: duduckgo"
	y_e "3: economist"
	y_e "4: facebook"
	y_e "5: googel and zhwikipedia"
	y_e "6: instagram"
	y_e "7: thepiratebay"
	y_e "8: thumblr"
	y_e "9: twitter moblie"
	y_e "10: twitter pc"
	y_e "11: youtube"
	y_e "12: youtube mobile"
	y_e "=========================================="
	sites={'archive_org' 'dropbox' 'duckduckgo' 'economist' 'facebook' 'google_and_zhwikiepdia' 'instagram' 'thepiratebay' 'thumblr' 'twitter_mobile' 'twitter_pc' 'youtube' 'youtube_mobile'}
	read -p "please enter which mirror you want to install:" site
	for "${site}" in "${sites}" do
	if [ ! -d "/home/${ngx_user}/site/${domain}/${site}"]; then
		r_e "The site you specified has been installed already, nothing to do."
		exit 1
	else
		case "${site}" in
			0)
				git clone https://github.com/aploium/zmirror.git ${sites[0]}
		  		cd ${sites[0]}
				python3.6 -m pip install virtualenv setuptools==21
				virtualenv -p python3.6 venv
				./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
				./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
				cp more_configs/config_${sites[0]}.py config.py
				sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
				sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
				cat>/lib/systemd/system/${sites[0]}.service<<EOF
					[unit]
					Description= Auto start for mirror ${sites[0]}
					After=network.target
					[Service]
					Restart=On-ailure
					WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[0]}
					ExecStart=/home/${ngx_user}/site/${domain}/${sites[0]}/venv/bin/gunicorn --log-file zmirror_${sites[0]}.log --access-logfile zmirror_access_${sites[0]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
					[Install]
					WantedBy=multi-user.target

EOF
				systemctl enable ${sites[0]}.service
				systemctl start ${sites[0]}.service
			;;
                	1)
                        	git clone https://github.com/aploium/zmirror.git ${sites[1]}
                        	cd ${sites[1]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[1]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[1]}.service<<EOF
                                	[unit]
                                	Description= Auto start for mirror ${sites[1]}
                                	After=network.target
                                	[Service]
                                	Restart=On-ailure
                                	WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[1]}
                               		ExecStart=/home/${ngx_user}/site/${domain}/${sites[1]}/venv/bin/gunicorn --log-file zmirror_${sites[1]}.log --access-logfile zmirror_access_${sites[1]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                	[Install]
                                	WantedBy=multi-user.target

EOF
                        	systemctl enable ${sites[1]}.service
                        	systemctl start ${sites[1]}.service

                        ;;
                	2)
                        	git clone https://github.com/aploium/zmirror.git ${sites[2]}
                        	cd ${sites[2]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[2]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[2]}.service<<EOF
                        	        [unit]
                        	        Description= Auto start for mirror ${sites[2]}
                        	        After=network.target
                        	        [Service]
                        	        Restart=On-ailure
                        	        WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[2]}
                                	ExecStart=/home/${ngx_user}/site/${domain}/${sites[2]}/venv/bin/gunicorn --log-file zmirror_${sites[2]}.log --access-logfile zmirror_access_${sites[2]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                	[Install]
                                	WantedBy=multi-user.target

EOF
                        	systemctl enable ${sites[2]}.service
                        	systemctl start ${sites[2]}.service

                        ;;
                	3)
                        	git clone https://github.com/aploium/zmirror.git ${sites[3]}
                        	cd ${sites[3]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[3]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[3]}.service<<EOF
                        	        [unit]
                        	        Description= Auto start for mirror ${sites[3]}
                        	        After=network.target
                        	        [Service]
                        	        Restart=On-ailure
                        	        WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[3]}
                                	ExecStart=/home/${ngx_user}/site/${domain}/${sites[3]}/venv/bin/gunicorn --log-file zmirror_${sites[3]}.log --access-logfile zmirror_access_${sites[3]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                	[Install]
                                	WantedBy=multi-user.target

EOF
                        	systemctl enable ${sites[3]}.service
                        	systemctl start ${sites[3]}.service

                        ;;
                	4)
                        	git clone https://github.com/aploium/zmirror.git ${sites[4]}
                        	cd ${sites[4]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[4]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[4]}.service<<EOF
                        	        [unit]
                               		Description= Auto start for mirror ${sites[4]}
                                	After=network.target
                                	[Service]
                                	Restart=On-ailure
                                	WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[4]}
                                	ExecStart=/home/${ngx_user}/site/${domain}/${sites[4]}/venv/bin/gunicorn --log-file zmirror_${sites[4]}.log --access-logfile zmirror_access_${sites[4]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                	[Install]
                                	WantedBy=multi-user.target

EOF
        	                systemctl enable ${sites[4]}.service
	                        systemctl start ${sites[4]}.service

                        ;;
                	5)
                	        git clone https://github.com/aploium/zmirror.git ${sites[5]}
                	        cd ${sites[5]}
                	        python3.6 -m pip install virtualenv setuptools==21
                	        virtualenv -p python3.6 venv
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                	        cp more_configs/config_${sites[5]}.py config.py
                	        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                	        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                	        cat>/lib/systemd/system/${sites[5]}.service<<EOF
                	                [unit]
                	                Description= Auto start for mirror ${sites[5]}
                	                After=network.target
                	                [Service]
                	                Restart=On-ailure
                	                WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[5]}
                	                ExecStart=/home/${ngx_user}/site/${domain}/${sites[5]}/venv/bin/gunicorn --log-file zmirror_${sites[5]}.log --access-logfile zmirror_access_${sites[5]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                	[Install]
                                	WantedBy=multi-user.target

EOF
	                        systemctl enable ${sites[5]}.service
	                        systemctl start ${sites[5]}.service

                        ;;
	                6)
        	                git clone https://github.com/aploium/zmirror.git ${sites[6]}
                	        cd ${sites[6]}
                	        python3.6 -m pip install virtualenv setuptools==21
                	        virtualenv -p python3.6 venv
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                	        cp more_configs/config_${sites[6]}.py config.py
                	        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                	        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                	        cat>/lib/systemd/system/${sites[6]}.service<<EOF
              		                [unit]
                        	        Description= Auto start for mirror ${sites[6]}
                           	 	After=network.target
					[Service]
                                	Restart=On-ailure
                                	WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[6]}
                                ExecStart=/home/${ngx_user}/site/${domain}/${sites[6]}/venv/bin/gunicorn --log-file zmirror_${sites[6]}.log --access-logfile zmirror_access_${sites[6]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                [Install]
                                WantedBy=multi-user.target

EOF
                        systemctl enable ${sites[6]}.service
                        systemctl start ${sites[6]}.service

                        ;;
                7)
                        git clone https://github.com/aploium/zmirror.git ${sites[7]}
                        cd ${sites[7]}
                        python3.6 -m pip install virtualenv setuptools==21
                        virtualenv -p python3.6 venv
                        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        cp more_configs/config_${sites[7]}.py config.py
                        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        cat>/lib/systemd/system/${sites[5]}.service<<EOF
                                [unit]
                                Description= Auto start for mirror ${sites[7]}
                                After=network.target
                                [Service]
                                Restart=On-ailure
                                WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[7]}
                                ExecStart=/home/${ngx_user}/site/${domain}/${sites[7]}/venv/bin/gunicorn --log-file zmirror_${sites[7]}.log --access-logfile zmirror_access_${sites[7]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                [Install]
                                WantedBy=multi-user.target

EOF
                        systemctl enable ${sites[7]}.service
                        systemctl start ${sites[7]}.service

                        ;;
                8)
                        git clone https://github.com/aploium/zmirror.git ${sites[8]}
                        cd ${sites[8]}
                        python3.6 -m pip install virtualenv setuptools==21
                        virtualenv -p python3.6 venv
                        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        cp more_configs/config_${sites[8]}.py config.py
                        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        cat>/lib/systemd/system/${sites[8]}.service<<EOF
                                [unit]
                                Description= Auto start for mirror ${sites[8]}
                                After=network.target
                                [Service]
                                Restart=On-ailure
                                WorkingDirectory=/home/${ngx_usr}/site/${domain}/${sites[8]}
                                ExecStart==/home/${ngx_usr}/site/${domain}/${sites[8]}/venv/bin/gunicorn --log-file zmirror_${sites[8]}.log --access-logfile zmirror_access_${sites[8]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                [Install]
                                WantedBy=multi-user.target

EOF
                        systemctl enable ${sites[8]}.service
                        systemctl start ${sites[8]}.service

                        ;;
                9)
                        git clone https://github.com/aploium/zmirror.git ${sites[9]}
                        cd ${sites[5]}
                        python3.6 -m pip install virtualenv setuptools==21
                        virtualenv -p python3.6 venv
                        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        cp more_configs/config_${sites[9]}.py config.py
                        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        cat>/lib/systemd/system/${sites[9]}.service<<EOF
                                [unit]
                                Description= Auto start for mirror ${sites[9]}
                                After=network.target
                                [Service]
                                Restart=On-ailure
                                WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[9]}
                                ExecStart=/home/${ngx_user}/site/${domain}/${sites[9]}/venv/bin/gunicorn --log-file zmirror_${sites[9]}.log --access-logfile zmirror_access_${sites[9]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                [Install]
                                WantedBy=multi-user.target

EOF
                        systemctl enable ${sites[9]}.service
                        systemctl start ${sites[9]}.service

                        ;;
                	10)
                        	git clone https://github.com/aploium/zmirror.git ${sites[10]}
                        	cd ${sites[10]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[10]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[10]}.service<<EOF
                        	        [unit]
                        	        Description= Auto start for mirror ${sites[10]}
                        	        After=network.target
                        	        [Service]
                        	        Restart=On-ailure
                        	        WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[10]}
                                ExecStart==/home/${ngx_usr}/site/${domain}/${sites[10]}/venv/bin/gunicorn --log-file zmirror_${sites[10]}.log --access-logfile zmirror_access_${sites[10]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                                [Install]
                                WantedBy=multi-user.target

EOF
                        systemctl enable ${sites[10]}.service
                        systemctl start ${sites[10]}.service

                        ;;
                	11)
                        	git clone https://github.com/aploium/zmirror.git ${sites[11]}
                        	cd ${sites[11]}
                        	python3.6 -m pip install virtualenv setuptools==21
                        	virtualenv -p python3.6 venv
                        	./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                        	./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                        	cp more_configs/config_${sites[11]}.py config.py
                        	sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                        	sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                        	cat>/lib/systemd/system/${sites[11]}.service<<EOF
                        	        [unit]
                        	        Description= Auto start for mirror ${sites[11]}
                        	        After=network.target
                        	        [Service]
                        	        Restart=On-ailure
                        	        WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[11]}
                        	        ExecStart=/home/${ngx_user}/site/${domain}/${sites[11]}/venv/bin/gunicorn --log-file zmirror_${sites[11]}.log --access-logfile zmirror_access_${sites[11]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                        	        [Install]
                        	        WantedBy=multi-user.target

EOF
                        	systemctl enable ${sites[11]}.service
                        	systemctl start ${sites[11]}.service

                        ;;
                	12)
                	        git clone https://github.com/aploium/zmirror.git ${sites[12]}
                	        cd ${sites[12]}
                	        python3.6 -m pip install virtualenv setuptools==21
                	        virtualenv -p python3.6 venv
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple gunicorn gevent
                	        ./venv/bin/pip install -i https://pypi.douban.com/simple -r requirements.txt
                	        cp more_configs/config_${sites[12]}.py config.py
                	        sed -i "s#my_host_name='127.0.0.1'#my_host_name='${domain}'#g" config.py
                	        sed -i "S#my_host_scheme='http://'#my_host_scheme='https://'#/g" config.py
                	        cat>/lib/systemd/system/${sites[12]}.service<<EOF
                	                [unit]
                	                Description= Auto start for mirror ${sites[12]}
                	                After=network.target
                	                [Service]
                	                Restart=On-ailure
                	                WorkingDirectory=/home/${ngx_user}/site/${domain}/${sites[12]}
                	                ExecStart=/home/${ngx_user}/site/${domain}/${sites[12]}/venv/bin/gunicorn --log-file zmirror_${sites[12]}.log --access-logfile zmirror_access_${sites[12]}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
                	                [Install]
                	                WantedBy=multi-user.target

EOF
                	        systemctl enable ${sites[11]}.service
                	        systemctl start ${sites[11]}.service

                        ;;
			*)
				echo "you don't choose a site to install, this will install google and zhwikipedia by default"
				site="5"
			;;
	esac
	fi
	done
