#! /bin/bash

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
 else
	 G_E "Ok, please make sure you can remeber this port!"
	 G_E "Pleae change the port in your ssh client to the new port!"
 fi
 sed -i "s/# Port 22/Port \${sshPort}/g" /etc/ssh/sshd_config
 sed -i "s/# PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
 sed -i "s/# AllowPassword yes/AllowPassword no/g" /etc/ssh/sshd_config
 sed -i "s/# PublicKeyLogin no/PublicKeyLogin yes/g" etc/ssh/sshd_config
 systemctl enable firewalld 
 service firewalld start
 cp /usr/lib/firewalld/service/ssh.xml /etc/firewalld/service/
 sed -i "s/port=22/port=\${sshPort}/g"
 service firewalld reload
 service ssh reload
 G_E "Ok, the SSH has been modified successfully"

