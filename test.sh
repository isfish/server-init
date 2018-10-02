#!/bin/bash

if grep -qi "www" /etc/passwd; then
	echo "true"
else
	echo "false"
fi

if grep -qi "wwww" /etc/passwd; then 
	echo "1"
else
	echo "0"
fi
