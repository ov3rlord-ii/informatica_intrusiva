#!/bin/bash

#Se guarda el primer argumento y incluye el ciclo del escaneo TCP
#reemplazando la variable 192.168.1.$ip por $addr, el resto se mantiene
#igual para la iteracion sobre las conexiones con nc

function tcp_scan(){
	addr=$1
	printf "\t<TCP scan in progress for $addr>\n"
  
  	#Ciclo para iterar sobre los puertos, anidado en el ciclo de las IP, 
  	#se recorre por cada IP
	
  	for port in $(seq 1 1024);do
		pstatus=$(nc -zvw 1 $addr $port 2>&1 | grep -Po "succeeded")
		if [[ $pstatus == succeeded ]];then
			printf "\t\t[*]$port/tcp $pstatus\n"
		fi
	done
}

#Se itera sobre una red 192.168.1.0/24 empleado el comando seq
#para generar numeros de 1 a 254

for ip in $(seq 1 254);do
    hstatus=$(ping -c 1 "192.168.1.$ip" | grep -Po "[0-1]+ received" | cut -d " " -f 1)
    if [[ hstatus -eq 1 ]];then
        printf "[ICMP_UP] 192.168.1.$ip\n"
	tcp_scan 192.168.1.$ip
    else
        #Se cambia el comando echo por printf para imprimir sobre la misma
        #linea y se ejecuta el comando arp sobre la IP que se esta escaneando,
        #con regexp extraemos la MAC, si hay MAC se muestra en estado ARP_UP
        
        printf "[ICMP_DOWN] "
	mac_addr=$(arp 192.168.1.$ip | grep -Po "([0-9a-fA-F]{2}:?){6}")
	if [[ $mac_addr ]]; then
		printf "| [ARP_UP] 192.168.1.$ip\n"
		tcp_scan 192.168.1.$ip
	else
		printf "| [ARP_DOWN] 192.168.1.$ip\n"
	fi
    fi
done
