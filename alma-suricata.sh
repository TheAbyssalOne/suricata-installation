#!/bin/bash
# Written by Giovanni Aramu
# Version 0.5
# This script will install Suricata on RHEL, Alma & Rocky Linux 9
# the script will set an adapter in promiscuous mode to monitor for all traffic
# The script will update the Suricata rules to the latest Emerging Threats Open Ruleset
# The script will also test Suricata with testmyids rule
# Suricata is pre-configured to run as the suricata user.
# Command line parameters such as providing the interface names can be configured in /etc/sysconfig/suricata.
# Users can run suricata-update without being root provided they are added to the suricata group.

######################################### Suricata Comments #####################################
# Directories:
# /etc/suricata: Configuration directory
# /var/log/suricata: Log directory
# /var/lib/suricata: State directory rules, datasets.
# enable all rules sources with the following commands
# sudo suricata-update enable-source et/open && \
# sudo suricata-update enable-source oisf/trafficid && \
# sudo suricata-update enable-source sslbl/ssl-fp-blacklist && \
# sudo suricata-update enable-source sslbl/ja3-fingerprints && \
# sudo suricata-update enable-source etnetera/aggressive && \
# sudo suricata-update enable-source tgreen/hunting && \
# sudo suricata-update enable-source malsilo/win-malware && \
# sudo suricata-update enable-source stamus/lateral && \
# sudo suricata-update enable-source pawpatrules

######################################### Evebox Comments ######################################
# https://evebox.org/docs/install/debian
# https://docs.suricata.io/en/latest/install.html
# execute the script with root privilege
# adapter must be in promiscuous mode, set it with 'ip link set <addnfer> promisc on'
# evebox server -D . --datastore sqlite --host 0.0.0.0 --input /var/log/suricata/eve.json for evebox server configuration on localhost suricata server
# credentials for evebox server: wil be generated and shown on the terminal after evebox server installation in admin:password format

  
set -euo pipefail

cat << "EOF" 
  ____                _              _           _____                
 / ___|  _   _  _ __ (_)  ___  __ _ | |_  __ _  |___  |               
 \___ \ | | | || '__|| | / __|/ _` || __|/ _` |    / /                
  ___) || |_| || |   | || (__| (_| || |_| (_| |   / /                 
 |____/  \__,_||_|   |_| \___|\__,_| \__|\__,_|  /_/                  
  ___              _          _  _   ____               _         _   
 |_ _| _ __   ___ | |_  __ _ | || | / ___|   ___  _ __ (_) _ __  | |_ 
  | | | '_ \ / __|| __|/ _` || || | \___ \  / __|| '__|| || '_ \ | __|
  | | | | | |\__ \| |_| (_| || || |  ___) || (__ | |   | || |_) || |_ 
 |___||_| |_||___/ \__|\__,_||_||_| |____/  \___||_|   |_|| .__/  \__|
  _               ___          _         _                |_|         
 | |__   _   _   / _ \  _   _ (_) _ __  | |_  ___   _ __              
 | '_ \ | | | | | | | || | | || || '_ \ | __|/ _ \ | '__|             
 | |_) || |_| | | |_| || |_| || || | | || |_| (_) || |                
 |_.__/  \__, |  \__\_\ \__,_||_||_| |_| \__|\___/ |_|                
         |___/        
EOF

check_root() {
	if [[ $EUID -ne 0 ]]; then
	   echo "[-] This script must be run as root"
	   exit 1
	fi
}

check_update() {
	dnf update
}

check_sudo() {
	# check sudo installation
	if ! [ -x "$(command -v sudo)" ]; then
		echo "sudo is not installed, installing sudo"
		dnf install -y sudo
	fi
}

check_iface() {
	
	IfaceAll=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
	CountIface=$(wc -l <<< "${IfaceAll}")
	if [[ $CountIface -eq 1 ]]; then
		LIFACE=$IfaceAll
	else
		for iface in $IfaceAll
		do 
			echo "Available interface: ""$iface"
		done
		echo ""
	
		echo "Which Interface you want suricata to Listen(cdnfured)?"
		read -p "Interface: " LIFACE
		# adapter can be set to promiscuous mode to monitor all traffic, not just traffic to the host, set it with 'ip link set <adapter> promisc on'
		# check if the interface is in promiscuous mode
		IPROM=$(ip link show $LIFACE | grep -i "PROMISC" | wc -l)
		if [[ $IPROM -eq 0 ]]; then

		
		# set promiscuous mode on the interface
		ip link set dev $LIFACE promisc on
	fi
}

install_suricata() {
	
	# install with RPM package
	dnf install -y epel-release dnf-plugins-core
	dnf copr enable @oisf/suricata-7.0
	dnf update -y
	dnf -y install suricata
	systemctl stop suricata
	systemctl enable suricata

	# # config suricata
	# mv /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
	# cp conf/suricata.yaml /etc/suricata/
	# sed -i "s/CHANGE-IFACE/$LIFACE/g" /etc/suricata/suricata.yaml

	# # add support for cloud server type
	# PUBLIC=$(curl -s ifconfig.me)
	# LOCAL=$(hostname -I | cut -d' ' -f1)
	# DEFIP="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
	# LOCIP="$LOCAL/24"

	# if [[ $LOCAL = $PUBLIC ]];then
	# 	sed -i "s~IP-ADDRESS~$LOCIP~" /etc/suricata/suricata.yaml
	# else
	# 	sed -i "s~IP-ADDRESS~$DEFIP~" /etc/suricata/suricata.yaml
	# fi
	
	# update suricata rules with 'suricata-update' command
	# currently using rules source from 'Emerging Threats Open Ruleset'
	# -D command to specify directory from default value '/var/lib/suricata' to '/etc/suricata/'
	suricata-update -D /etc/suricata/ enable-source et/open
	suricata-update -D /etc/suricata/ update-sources
	# --no-merge command 'Do not merge the rules into a single rule file'
	# Detail on suricata-update command 'https://suricata-update.readthedocs.io/en/latest/update.html'
	suricata-update -D /etc/suricata/ --no-merge


	# enable suricata at startup
	systemctl enable suricata

	# start suricata
	systemctl start suricata

	# print suricata version
	suricata -V
	systemctl reload-or-restart suricata
	echo "Suricata has been installed and configured."
	echo "Suricata is monitoring on interface $LIFACE."
	echo "Please refer to the Suricata documentation for further configuration."

	# testing suricata with testmyids rule
	curl http://testmynids.org/uid/index.html
	echo "checking suricata log, exit with ctrl+c"
	tail -f /var/log/suricata/fast.log	

}

install_evebox() {
	# install evebox When started from systemd, the EveBox server will run as the user evebox which has write access to /var/lib/evebox.
	rpm -Uvh https://evebox.org/files/rpm/stable/evebox-release.noarch.rpm
	dnf update -y
	yum install -y evebox
	systemctl enable evebox
	systemctl start evebox
	echo "Evebox has been installed and started."
}

main() {

	#check root
	check_root

	# check sudo installation
	check_sudo

	# update
	check_update

	# check interface
	check_iface

	# install suricata 
	install_suricata	

	# install evebox
	install evebox
	
}

main
