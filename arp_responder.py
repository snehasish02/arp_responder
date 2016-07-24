from scapy.all import *
import threading
import sys
import socket
import socket
import subprocess

# mac_addr = "32:32:32:32:32:32"
def respond_arp(pkt):
	print pkt.summary() # op=1 who has, 2 is at
	if pkt[ARP].op == 1:
		intf, mac_addr, external_ip = get_interface_info(str(pkt[ARP].pdst))
		arp_res_pkt = eval(pkt.command())
		arp_res_pkt[ARP].op = 2
		arp_res_pkt[ARP].hwdst = pkt[ARP].hwsrc
		arp_res_pkt[ARP].pdst = pkt[ARP].psrc
		arp_res_pkt[ARP].psrc = pkt[ARP].pdst
		arp_res_pkt[ARP].hwsrc = mac_addr

		arp_res_pkt[Ether].dst = pkt[Ether].hwsrc
		arp_res_pkt[Ether].src = mac_addr
		print arp_res_pkt.show(), pkt.show()
		sendp(arp_res_pkt)

def start_thread(pkt):
	t = threading.Thread(target=respond_arp, args=(pkt,))
	t.start()

def sniff_arp(pkt_filter=None, iface=None):
	if pkt_filter is not None:
		sniff(filter=pkt_filter, prn=start_thread, store=0, count=0)
	else:
		pass

def valid_ip(ip):
    parts = ip.split('.')
    return (len(parts) == 4 and all(part.isdigit() for part in parts) and all(0 <= int(part) <= 255 for part in parts))

def create_ip_mappings(args):
	pass

def run_subprocess(command, check_error = False):
    p = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    (output,err) = p.communicate()
    if check_error is True:
        return_value = p.returncode
        try:
            code = int(return_value)
            assert code == 0
        except Exception as ex:
            raise Exception("Failed in executing the command: " + str(command))
    return (output,err)

def get_external_interface_ip(ip):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		try:
			sock.connect((ip, 80))
		except Exception:
			sock.connect((ip, 443))
	except Exception as e:
		raise Exception("The IP " + str(ip) + " is not accessible from this server, please check!", str(e))
		sys.exit(-1)
	return sock.getsockname()[0]

def get_mac_address(intf):
	mac_cmd = "cat /sys/class/net/" + intf + "/address"
	(stdout, stderr) = run_subprocess(command = mac_cmd, check_error = True)
	mac_addr = str(stdout.strip().lstrip().rstrip())
	return mac_addr

def get_interface_info(server_ip):
	external_ip = get_external_interface_ip(server_ip)
	interface_cmd = "netstat -ie | grep -B1 " + external_ip + " | head -n1 | awk {'print $1'}"
	(stdout, stderr) = run_subprocess(command = interface_cmd, check_error = True)
	intf = str(stdout.strip().lstrip().rstrip())
	mac_addr = get_mac_address(intf)
	return (intf, mac_addr, external_ip)

def validate_args(args):
	if len(args) > 1:
		if str(args[1]).lower() == "all":
			pass
		else:
			for ip in args[1:]:
				if not valid_ip(ip):
					raise Exception("Invalid argument passed. Expected  an ip got " + str(ip))
	else:
		raise Exception("\nNo arguments passed.\nUsage: pyhton arp_responder.py {all | ip1[ ip2[ ip3[ ...]]]}")

if __name__ == '__main__':
    validate_args(sys.argv)
    if str(sys.argv[1]).lower() == "all":
    	pkt_filter = None
    else:
		pkt_filter = "arp and host " + " or ".join(sys.argv[1:])
		# create_ip_mappings(sys.argv)
    sniff_arp(pkt_filter=pkt_filter)