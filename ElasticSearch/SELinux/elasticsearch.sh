#!/bin/bash

#Compile the Policy Package
#Source: https://serverfault.com/questions/806596/selinux-how-to-create-a-new-file-type
make -f /usr/share/selinux/devel/Makefile elasticsearch.pp

#Install the module
#https://debian-handbook.info/browse/stable/sect.selinux.html
sudo semodule -i elasticsearch.pp

#Load the new policy into the kernel
sudo load_policy

#Map the ElasticSearch ports to the port type
sudo semanage port -a -t elasticsearch_port_t 9200 -p tcp
sudo semanage port -a -t elasticsearch_port_t 9300-9310 -p tcp

#Relabel the files of The Hive
sudo restorecon -R /etc/elasticsearch
sudo restorecon -R /usr/share/elasticsearch
sudo restorecon -R /var/run/elasticsearch/elasticsearch.pid
sudo restorecon -R /var/log/elasticsearch
sudo restorecon -R /var/lib/elasticsearch