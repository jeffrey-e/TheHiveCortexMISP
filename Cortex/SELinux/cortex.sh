#!/bin/bash

#Compile the Policy Package
#Source: https://serverfault.com/questions/806596/selinux-how-to-create-a-new-file-type
make -f /usr/share/selinux/devel/Makefile cortex.pp

#Install the module
#https://debian-handbook.info/browse/stable/sect.selinux.html
sudo semodule -i cortex.pp

#Load the new policy into the kernel
sudo load_policy

#Relabel the files of The Hive
sudo restorecon -R /opt/cortex
sudo restorecon -R /etc/cortex
sudo restorecon -R /var/log/cortex

#Optional when you use a non reserved port (when building a Allin1 for example)
sudo semanage port -a -t cortex_port_t 9002 -p tcp