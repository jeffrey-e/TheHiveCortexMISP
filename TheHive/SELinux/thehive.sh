#!/bin/bash

#Compile the Policy Package
#Source: https://serverfault.com/questions/806596/selinux-how-to-create-a-new-file-type
make -f /usr/share/selinux/devel/Makefile thehive.pp

#Install the module
#https://debian-handbook.info/browse/stable/sect.selinux.html
sudo semodule -i thehive.pp

#Load the new policy into the kernel
sudo load_policy

#Relabel the files of The Hive
sudo restorecon -R /opt/thehive