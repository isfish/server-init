# !/bin/bash
# Description: A script is used to monitor the zmirror service depolyed in your VPS
# Author: isfish
# Version: 1.0
# Revision:
#	1.0 at 2018-12-02 1st release
###################################################################################

 PATH=PATH:~/bin
 export PATH
 if [ -s /usr/lib/systemd/system/google_and_zhwikipedia ]; then
	 service google_and_zhwikipedia status | 2>&1 1>/dev/null
	 if [ $? !-eq 0 ]; then
		 service google_and_zhwikipedia stop | 2>&1 1>/dev/null
		 service google_and_zhilikipeddia start | 2>&1 1>/devl/null
	 fi
 else
	echo "Sorry, service no exit!"
fi	
