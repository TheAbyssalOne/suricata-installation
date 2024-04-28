#!/bin/bash
# Written by NN-DF & G.P.Aramu
# Version 1.0
# This script is to install Suricata on Ubuntu 22.04 LTS
# Suricata is a free and open source, mature, fast and robust network threat detection engine
# The script will install Suricata with the latest version and configure it to monitor on the specified interface
# The script will also update the Suricata rules with the latest rules from Emerging Threats Open Ruleset
# The script will also test Suricata with testmyids rule

set -euo pipefail

check_root() {
	if [[ $EUID -ne 0 ]]; then
	   echo "[-] This script must be run as root"
	   exit 1
	fi
}

check_update() {

	apt update
}

check_iface() {
	
	IfaceAll=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
	CountIface=$(wc -l <<< "${IfaceAll}")
	if [[ $CountIface -eq 1 ]]; then
		LIFACE=$IfaceAll
	else
		for iface in $IfaceAll
		do 
			echo "Available interface: "$iface
		done
		echo ""
	
		echo "Which Interface you want suricata to Listen(captured)?"
		read -p "Interface: " LIFACE
	fi
}

install_suricata() {
	
	# install dependencies
	apt -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev \
	libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libmagic-dev libcap-ng-dev libjansson4 libjansson-dev pkg-config \
	rustc cargo libnetfilter-queue-dev geoip-bin geoip-database geoipupdate apt-transport-https libnetfilter-queue-dev \
        libnetfilter-queue1 libnfnetlink-dev tcpreplay curl

	# install with ubuntu package
	add-apt-repository -y ppa:oisf/suricata-stable
	apt update -y
	apt -y install suricata
	
	# stop suricata
	systemctl stop suricata

	# config suricata
	mv /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
	cp conf/suricata.yaml /etc/suricata/
	sed -i "s/CHANGE-IFACE/$LIFACE/g" /etc/suricata/suricata.yaml

	# add support for cloud server type
	PUBLIC=$(curl -s ifconfig.me)
	LOCAL=$(hostname -I | cut -d' ' -f1)
	DEFIP="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
	LOCIP="$LOCAL/24"

	if [[ $LOCAL = $PUBLIC ]];then
		sed -i "s~IP-ADDRESS~$LOCIP~" /etc/suricata/suricata.yaml
	else
		sed -i "s~IP-ADDRESS~$DEFIP~" /etc/suricata/suricata.yaml
	fi
	
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
	systemctl restart suricata
	echo "Suricata has been installed and configured."
	echo "Suricata is monitoring on interface $LIFACE."
	echo "Please refer to the Suricata documentation for further configuration."

	# testing suricata with testmyids rule
	curl http://testmynids.org/uid/index.html
	echo "checking suricata log, exit with ctrl+c"
	tail -f /var/log/suricata/fast.log	

}

main() {

	#check root
	check_root

	# update
	check_update

	# check interface
	check_iface

	# install suricata 
	install_suricata	
}

main
