#!/bin/bash
tests="home"
remote="paths"
if env | grep -i "$tests" && env | grep -i "$remote"; then 
	echo "true"
else
	echo "false"
fi

remote="555555"

