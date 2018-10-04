#!/bin/bash
echo "Welocme, I am ready to encrypt a file/directory for you"
echo "currently I have a limitation, Place me to the same folder, where a file to be encrypted is present"
echo "Enter the exact file name with extension"
read file
gpg -c $file
echo "I have encrypted the file successfully..."
echo "Now I will be removing the original file"
rm -rf $file

