#! /bin/bash
# Description: This script is used to deploy zmirrors
# Version: v2.1(rewrite from zms_dep.sh)
# Reversion:
#	v2.1 at 2018-12-12 create the unified preamble
########################################################################

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
 R_E(){
	echo -e "\e[1;31m$1\e[0m"
 }
 G_E(){
	echo -e "\e[1;32m$1\e[0m"
 }
 Y_E(){
	echo -e "\e[1;33m$1\e[0m"
 }
 B_E(){
	echo -e "\e[1;34m$1\e[0m"
 }
 ngx_loc="/usr/local/nginx"
 B_E "Install zmirrors..."
 if [ $(id -u) != "0" ]; then
	R_E "Sorry, this script must run by root. Please change to root to run this script!"
	exit 1
 fi
 B_E "[-] configure a certificate for the domain"
 read -p "Please enter a sub-domain for mirror(like a.abc.com):" domain
 if [ -s ${ngx_loc}/conf/vhosts/${domain}.conf ]; then
	R_E "The domain exist, exit"
	exit 1
 fi
 if [ -d /usr/local/acme/certs/${domain} ]; then
	G_E "=========================================================================================="
	G_E "=== The domain you input here has a certificate, it'll will not be issued, but will be ==="
	G_E "=== used in .conf file of nginx. Please specify the location of ssl certificat manually==="
	G_E "=========================================================================================="
		read -p "Please input the full location of your public key(like /home/www/mypub.pem):" pub_key
		read -p "Please input the full location of your private key(like /home/www/mypub.pem):" priv_key
		if [[ "${pub_key}" = "" || "${priv_key}" = "" ]]; then
			G_E "None of the public key or private key can be blank, you must specify both of them!"
			exit 1
		elif [[ ! -s "${pub_key}" && ! -s "${priv_key}" ]]; then
			G_E "The certifcate you specify is not found, please make suere you has enter a right location."
			exit 1
		else
			R_E "Ok, this is certificate will be used later."
		fi
 else
	read -p "Enter your dns server(like dns_dp):" dns_server
	read -p "Enter the dns api in the some form as you do before(like, DP_Id, DP_Key):" dns_id dns_key
		if [[ "${dns_server}" = "" ||  "${dns_id}" = ""  || "${dns_key}" = ""  ]]; then
			R_E "None of infomation of dns api can leave as blank, please specify them correctly."
			exit 1
		else
			export ${dns_id}
			export ${dns_key}
			mkdir -p /home/www/ssl/${domain}
			/usr/local/acme/acme.sh --issue --dns ${dns_server} -d ${domain}
			/usr/local/acme/acme.sh --install-cert -d ${domain} --fullchain-file /home/www/ssl/${domain}/pubkey.pem --key-file /home/www/ssl/${domain}/privkey.pem --reloadcmd "service nginx force-reload"
		fi
 fi
 sites=("archive_org" "dropbox" "duckduckgo" "economist" "facebook" "google_and_zhwikipedia" "instagram" "thepiratebay" "thumblr" "twitter_mobile" "twitter_pc" "youtube" "youtube_mobile")
 Y_E "=========================================="
 Y_E "plase choose one site from list below"
 Y_E "the sites below you can choose to install."
 Y_E "1: ${sites[0]}"
 Y_E "2: ${sites[1]}"
 Y_E "3: ${sites[2]}"
 Y_E "4: ${sites[3]}"
 Y_E "5: ${sites[4]}"
 Y_E "6: ${sites[5]}"
 Y_E "7: ${sites[6]}"
 Y_E "8: ${sites[7]}"
 Y_E "9: ${sites[8]}"
 Y_E "10: ${sites[9]}"
 Y_E "11: ${sites[10]}"
 Y_E "12: ${sites[11]}"
 Y_E "13: ${sites[12]}"
 Y_E "=========================================="
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
    	13) 
		site=${sites[12]}
	;;
	*)
		r_e "sorry, sorry no mirror you specify, exit!"
		exit 1
	esac
	read -p "Specify port for mirror(like,8000):" port
	if [ "${port}" = " " ]; then
		R_E "Port no specify, exit"
		exit 1
	elif [ `lsof -i:${port}` ]; then
		if [ "$?" = 0 ]; then
			R_E "Port exist,exit"
		fi
	fi
		
	if [ -d /home/www/site/${domain} ]; then
		R_E "The domain exist, exit!"
		exit 1
	else
        	cd /home/www/site/
		git clone https://github.com/aploium/zmirror.git ${domain}
		cd ${domain}
		python3.6 -m pip install virtualenv setuptools==21
		virtualenv -p python3.6 venv
		./venv/bin/pip install gunicorn gevent
		./venv/bin/pip install -r requirements.txt
		cp more_configs/config_${site}.py config.py
		sed -i "s#my_host_name = '127.0.0.1'#my_host_name = '${domain}'#g" config.py
		sed -i "s#my_host_scheme = 'http://'#my_host_scheme = 'https://'#g" config.py
		cat>/lib/systemd/system/${site}.service<<EOF
[unit]
Description= Auto start for mirror ${site}
After=network.target
[Service]
Restart=On-failure
WorkingDirectory=/home/www/site/${domain}
ExecStart=/home/www/site/${domain}/venv/bin/gunicorn --log-file zmirror_${site}.log --access-logfile zmirror_access_${site}.log --bind 127.0.0.1:${port} --workers 2 --worker-connections 100 wsgi:application
[Install]
WantedBy=multi-user.target
EOF
		systemctl enable ${site}.service
		systemctl start ${site}.service
	fi

## intall certificate and configure nginx vitrual conf
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
        access_log     			logs/${domain}.log;
        add_header      		Strict-Transport-Security "max-age=15552000;";
	ssl_early_data			on;
        ssl_certificate 		/home/www/ssl/${domain}/pubkey.pem;
        ssl_certificate_key 		/home/www/ssl/${domain}/privkey.pem;
        ssl_ciphers     		[TLS13+AESGCM+AES128|TLS13+AESGCM+AES256|TLS13+CHACHA20]:[EECDH+ECDSA+AESGCM+AES128|EECDH+ECDSA+CHACHA20]:EECDH+ECDSA+AESGCM+AES256:EECDH+ECDSA+AES128+SHA:EECDH+ECDSA+AES256+SHA:[EECDH+aRSA+AESGCM+AES128|EECDH+aRSA+CHACHA20]:EECDH+aRSA+AESGCM+AES256:EECDH+aRSA+AES128+SHA:EECDH+aRSA+AES256+SHA:RSA+AES128+SHA:RSA+AES256+SHA:RSA+3DES;
        ssl_prefer_server_ciphers 	on;
        ssl_protocols           	TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_session_cache       	shared:SSL:50m;
        ssl_session_timeout     	1d;
}
EOF
chown -R www:www /home/www/site
service nginx reload
