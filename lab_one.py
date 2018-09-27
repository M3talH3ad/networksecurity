"""Onwer: Siddharth Sharma"""
"""You might need  to install ipaddress"""

from scapy.all import *
import ipaddress

class QuestionOne(object):
	"""docstring for QuestionOne"""
	def __init__(self, ip_address, mask='24', ports=[80]):
		self.ip_address = ip_address
		self.mask = mask
		self.ports = ports
		self.packet = None

	def appendIPLayer(self, ip_address, packet=None):
		"""Appends IP layer to the packet
		or returns the IP packet"""
		if not packet: return IP(dst=str(ip_address))
		else: return packet/IP(dst=str(ip_address))

	def appendTCPLayer(self, ports, packet):
		"""Appends TCP header to given packet 
		or returns the TCP header"""
		if not isinstance(ports, list): return "Please provide a list of ports!"
		if not packet: return TCP(dport=ports)
		else: return packet/TCP(dport=ports)	
	
	def definePacket(self):
		# print(type(self.packet))
		for b in self.packet:
			print(b.show())

	def getIPAddress(self):
		"""Returns sources and broadcast address 
		and all host in given IP and its mask"""
		ip = ipaddress.IPv4Network(self.ip_address+'/'+self.mask, strict=False)
		return {'sourceIPAddress': ip.network_address, 'broadcast_address': ip.broadcast_address, 'hosts': ip.hosts()}

	def run(self):
		address = self.getIPAddress()
		for index, host in enumerate(address['hosts']):
			for j, port in enumerate(self.ports):
				print("Start of packet with IP" , host , 'and TCP Port ', port)
				packet = self.appendIPLayer(host)
				packet = self.appendTCPLayer([port], packet)
				print(packet.show())
				print("End of packet with IP" , host , 'and TCP Port ', port)
				print('----------------------------------------------------------')

	def prependEther(self, packet):
		"""Prepends Ether header to a packet"""
		if not packet: return Ether()
		else: Ether()/packet

class QuestionTwo(object):		

	def run(self, ip_address=None):

		if ip_address is None or len(ip_address) == '' or len(ip_address.split('.')) != 4: return "Not a valid IP Address"
		a = sr1(IP(dst=ip_address)/ICMP()/"XXXXXXXXXXX")
		print(a.show())


class QuestionThree(object):
	"""docstring for QuestionThree"""
	# def __init__(self, arg):
	# 	super(QuestionThree, self).__init__()
	# 	self.arg = arg

	def run(self, dest_ip_address, dport):
		"""Setting an IP TCP packet and sending to the client machine"""
		p=IP(dst=dest_ip_address, ttl=99)/TCP(sport=RandShort(),dport=dport, flags="S")/"Attack Atack!"
		print(ls(p))

		# Loop sending packets at an interval of 0.2 sec
		# srloop as we are sending packet at layer 3.
		ans,unans=srloop(p, inter=0.2,retry=2,timeout=3)
		print (ans.summary())
		print (unans.summary())



if __name__ == '__main__':
	# obj = QuestionOne('10.20.111.2', '30', [53, 80])
	# obj.run()

	# Please Run on vital
	# obj = QuestionTwo()
	# obj.run('8.8.8.8')

	# Please Run on vital
	# obj = QuestionThree()
	# obj.run('10.10.111.102', 139)
