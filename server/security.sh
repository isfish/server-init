#! /bin/bash
# Description: This script is used to change default SSH port, add a new user in wheel group(give this user sudo permission), prohibit login by passwd and root from remote login 
# Author: isfish
# Version: 1.0
# Date: 2018-11-30
# Reversion:
#	v1.0 at 2018-11-30 for first time release
#################################################################################################################################################################################



PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

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

 if [ $(id -u) != 0 ]; then
	 R_E "Sorry, please run this script as root!"
 fi
 B_E "This Script is used to bulid your vps security up..."

 read -p "Which port do you want to use as SSH port: " sshPort

 if [ -z ${sshPort} ]; then
	R_E "Sorry, the port should not be empty, program will exit..."
	exit 1
 else
	G_E "Ok, please make sure you can remeber this port!"
	G_E "Pleae change the port in your ssh client to the new port!"
 	sed -i "s/#Port 22/Port ${sshPort}/g" /etc/ssh/sshd_config
 	systemctl enable firewalld 
 	service firewalld start
 	cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/
	sed -i "s/port=\"22\"/port=\"${sshPort}\"/g" /etc/firewalld/services/ssh.xml
 	service firewalld reload
 	service sshd reload
 	G_E "Ok, the SSH has been modified successfully"
 fi
 B_E "Disable some choice"
 sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
 sed -i "s/PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
 sed -i "s/#PubkeyAuthentication no/PublicKeyLogin yes/g" /etc/ssh/sshd_config
 sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" /etc/ssh/sshd_config
 sed -i "s/#MaxSessions 10/MaxSessions 3/g" /etc/ssh/sshd_config
 read -p "Please enter the username your want to add(like mike): " userName
 if [ -z "$userName" ]; then
	R_E "Sorry, please enter a correct username!"
	exit 1
 elif grep -Eqi "$userName" /etc/passwd ; then
	R_E "Sorry, the ${userName} has already exist, nothing to do!"
 else 
	useradd -G wheel ${userName}
	G_E "Please enter the password twice now(The password will not show on the screen)"
	passwd ${userName}
 fi 
 read -p "Please input the public key generated in your local SSH clicent: " pubKey
 if [ ! -d /home/${userName}/.ssh ]; then 
	mkdir /home/${userName}/.ssh
	chmod 700 /home/${userName}/.ssh
 	if [ ! -s /home/${userName}/.ssh/authorized_keys ]; then
		touch /home/${userName}/.ssh/authorized_keys
		chmod 600 /home/${userName}/.ssh/authorized_keys
		if [ -z ${pubKey} ]; then
			R_E "You must input pulic key, and make sure it can work correctly."
			exit 1
		else 
			cat>>/home/${userName}/.ssh/authorized_keys<<EOF
${pubKey}
EOF
			chown ${userName}:${userName} -R /home/${userName}
		fi
	fi
 else
	if [ -z ${pubKey} ]; then
		R_E "You must input pulic key, and make sure it can work correctly."
		exit 1
	else
		cat>>/home/${userName}/.ssh/authorized_keys<<EOF
${pubKey}
EOF
		chown ${userName}:${userName} -R /home/${userName}
	fi
 fi
 G_E "Ok, all things done..."


 


