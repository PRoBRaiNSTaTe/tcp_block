from scapy.all import *
import sys

interface = sys.argv[1]
my_mac = get_if_hwaddr(interface)

FIN = 0X01
RST = 0X04
ACK = 0X10

def usage():
	print('syntax: python tcp_block.py <interface>')
	sys.exit(1)

def block_packet(Opacket):
	if (Ether in Opacket) and (IP in Opacket):
		if (Opacket[TCP].flags & FIN or Opacket[TCP].flags & RST):
			sendp(Opacket, iface = interface)
			return

		Fpacket = Opacket[Ether]/Opacket[IP]/Opacket[TCP]
		Fpacket[TCP].remove_payload()
		del Fpacket[TCP].chksum
		del Fpacket[IP].chksum
		Fpacket[Ether].src = my_mac
		payload_len = len(Opacket[TCP])
		if payload_len == 0:
			payload_len = 1
		Fpacket[TCP].seq += payload_len
		Fpacket[TCP].flags = RST | ACK
		Fpacket.show2()
		sendp(Fpacket, iface = interface)

		if ("HTTP" in str(Opacket)):
			Fpacket[TCP].flags = FIN | ACK
			data = "blocked\r\n"
			Fpacket = Fpacket / data
			print("HTTP Packet Blocked")
		else:
			print("TCP Packet Blocked")

		Fpacket[Ether].dst = Opacket[Ether].src
		Fpacket[IP].src = Opacket[IP].dst
		Fpacket[IP].dst = Opacket[IP].src
		Fpacket[TCP].seq = Opacket[TCP].ack
		Fpacket[TCP].ack = Opacket[TCP].seq + payload_len
		Fpacket.show2()
		sendp(Fpacket, iface = interface)

if __name__== "__main__":

	if len(sys.argv) != 2:
		usage()

	try:
		print('TCP packet is blocking')
		sniff(iface = interface, filter = 'tcp', prn = block_packet)
	
	except KeyboardInterrupt:
		print('EXIT')
		sys.exit(1)
