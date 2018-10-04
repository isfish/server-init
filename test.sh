#!/bin/bash
tests="8964"
remote="paths"
if netstat -ltnp | grep -Eqi ":$tests"; then 
	echo "true"
else
	echo "false"
fi


