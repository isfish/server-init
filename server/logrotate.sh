#! /bin/bash
# Descrition: A script used to rotate and compress log files.
# Author: isfish
# Version: v1.0
# Reversion: 
#	-v1.0 at 2018-12-26 create
###############################################################################

 WARNINFO(){
        echo -e "\e[1;31m$1\e[0m"
 }
 PATH=$PATH:~/bin
 export PATH
 if [ $(id -u) != 0 ]; then
	WARNINFO "Sorry, Please run this by root!"
	exit 1
 fi
	if [ ! -d /usr/local/logrotate ]; then
		mkdir /usr/local/logrotate
	fi
	cat>>/usr/local/logrotate/daily.conf<<EOF
/usr/local/nginx/logs/*.log{
	nomail
	rotate 15
	compress
	create
	dateext
	postrotate
        	if [ -f /usr/local/nginx/logs/nginx.pid ]; then
            		kill -USR1 `cat /usr/local/nginx/logs/nginx.pid`
        	fi
	endscript
 } 
/etc/v2ray/logs/*.log{
        nomail
        rotate 15
        compress
        create
        dateext
 } 
EOF


