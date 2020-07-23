#!/usr/bin/env python3

import argparse
import ipcalc
import sys
import re
import getpass
import readline
from netmiko import ConnectHandler
from netmiko.base_connection import BaseConnection
from netmiko import redispatch
from pprint import pprint
from socket import gethostbyaddr

#error suppressing
class DevNull:
    def write(self, _):
        pass

##########################################################################################################
#
#  Template/header for CSV file and pprint_template for plain screen output
#
##########################################################################################################

csv_header = "Device IP,Reverse DNS Name,MAC Address,Switch,Switch IP,Port,Port Description,Interface Type,Native or Access Vlan,Port MAC count\n"
csv_line_template = "{},{},{},{},{},{},{},{},{},{}\n"
pprint_template = "Device IP: {},Reverse DNS Name: {},MAC Address: {},Switch: {},Switch IP: {},Port: {},Port Description: {},Interface Type: {},Native or Access Vlan: {},Port MAC count: {}"

##########################################################################################################
#
#  Define Global Regexs
#
##########################################################################################################
ip_regex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
subnet_regex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.')
mac_regex = re.compile(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}')
int_regex = re.compile(r'Fa{1}\d+(/\d*)*|Gi{1}\d+(/\d*)*|Eth{1}\d+(/\d*)*|Te(nGigE)?\d+(/\d*)*|Hu(ndredGigE)?\d+(/\d*)*')
int_po_regex = re.compile(r'Po{1}\d+|Bundle-Ether{1}\d+')
vpc_pl_regex = re.compile(r'vPC Peer-Link')
int_regexes = [int_regex, int_po_regex, vpc_pl_regex]
description_regex = re.compile(r'Description: (.*)', re.MULTILINE)
access_vlan_regex = re.compile(r'switchport access vlan (\d+)', re.MULTILINE)
native_vlan_regex = re.compile(r'switchport trunk native vlan (\d+)', re.MULTILINE)
trunk_regex = re.compile(r'switchport mode trunk', re.MULTILINE)
ios_xr_regex = re.compile(r'IOS XR')
nxos_regex = re.compile(r'Nexus')

##########################################################################################################
#
#  Get arguments from the command line
#
##########################################################################################################

# determine if arguments were passed to the script and parse if so
if len(sys.argv) > 1:

	parser = argparse.ArgumentParser()

	parser.add_argument('-n', action='store', dest='network_to_scan',
						help='The network to scan in CIDR format example 192.168.10.0/24', required=True)

	parser.add_argument('-c', action='store', dest='core_switch',
						help='The IP address of the core switch to start the scan from', required=True)

	parser.add_argument('-u', action='store', dest='username',
						help='The username to connect with', required=True)

	parser.add_argument('-f', action='store', dest='filename',
						help='Optional file to output results to', default="")

	parser.add_argument('-v', action='store', dest='vrf',
						help='Optional VRF name', default="")

	try:
		options = parser.parse_args()
	except:
		parser.print_help()
		sys.exit(0)
	password = getpass.getpass()
	if options.vrf:
		current_vrf = options.vrf
		vrf = "vrf"
	else:
		current_vrf = ""
		vrf = ""
# if no arguments parsed, run interactive prompts
else:
	options = None
	network_to_scan = input("Enter target in CIDR notation (192.168.10.0/24): ")
	while not subnet_regex.match(network_to_scan):
		network_to_scan = input("Enter target in CIDR notation (192.168.10.0/24): ")
	current_vrf = input("Enter VRF for the IP (leave blank if not needed): ")
	if current_vrf == "":
		vrf = ""
	else:
		vrf = "vrf"
	core_switch = input("Enter the Default Gateway of target ip: ")
	while not ip_regex.match(core_switch):
		core_switch = input(
			"The entered value is not an IP address. Please re-enter the IP of the core router/switch: ")
	username = input("Username: ")
	password = getpass.getpass()
	filename = input("Enter a filename to save output as CSV (leave blank for no file output): ")


##########################################################################################################
#
#  RedispatchDeviceType - finds the correct device_type and returns a redispatched netmiko SSH conn object
#
##########################################################################################################
def RedispatchDeviceType(switch_ip, username, password):
	# Establish BaseConnection via SSH and issue show version to find correct device_type
	core_base_conn = BaseConnection(host=switch_ip, username=username, password=password)
	show_ver = core_base_conn.send_command("show version | inc Software", delay_factor=.1)
	
	ios_xr_search = ios_xr_regex.search(show_ver)
	nxos_search = nxos_regex.search(show_ver)
	if ios_xr_search:
		redispatch(core_base_conn, device_type="cisco_xr")
	elif nxos_search:
		redispatch(core_base_conn, device_type="cisco_nxos")
	else:
		redispatch(core_base_conn, device_type="cisco_ios")
	
	return core_base_conn


##########################################################################################################
#
#  GetInterfaceDescription - Returns description of interface as a string
#
##########################################################################################################
def GetInterfaceDescription(next_switch_conn, mac_port):
	# get the interface description
	interface_description = ''

	show_interface_description = next_switch_conn.send_command("show interface " + mac_port + " | inc Description", delay_factor=.1)
	interface_description_match = description_regex.search(show_interface_description)

	if interface_description_match:
		interface_description = interface_description_match.group(1)

	return interface_description


##########################################################################################################
#
#  GetInterfaceMode- Returns whether the interface is trunk or access and VLAN
#
##########################################################################################################
def GetInterfaceMode(next_switch_conn, mac_port):
	vlan = "1"
	
	# check whether the interface is a trunk
	show_run_interface = next_switch_conn.send_command("show run interface " + mac_port, delay_factor=.1)
	interface_trunk_match = trunk_regex.search(show_run_interface)
	
	# device is on a trunk port
	if interface_trunk_match:
		interface_type = "trunk"
		native_vlan_match = native_vlan_regex.search(show_run_interface)
		# find the native vlan of trunk if it exists
		if native_vlan_match:
			vlan = native_vlan_match.group(1)
			
	# device is on an access port
	else:
		interface_type = "access"
		show_run_interface_match = access_vlan_regex.search(show_run_interface)
		# find the access vlan if it exists
		if show_run_interface_match:
			vlan = show_run_interface_match.group(1)

	return interface_type, vlan


##########################################################################################################
#
#  GetMacCount- Returns count of MAC addressed on a port
#
##########################################################################################################
def GetMacCount(next_switch_conn, mac_port):
	mac_port_macs = next_switch_conn.send_command("show mac add int " + mac_port + "\n", delay_factor=.1)
	multi_macs = re.findall(mac_regex, mac_port_macs)
	return len(multi_macs)


##########################################################################################################
#
#  GetCDPNeighbor - Checks for CDP Neighbor on switch port
#
##########################################################################################################
def GetCDPNeighbor(device_type, next_switch_conn, mac_port):
	# Get the CDP neighbor IP from Nexus device
	if device_type == 'cisco_nxos':
		show_cdp_nei = next_switch_conn.send_command("show cdp nei int " + mac_port + " det | inc IP", delay_factor=.1)
	
	# Get the CDP neighbor IP from IOS/XR/XE device
	else:
		show_cdp_nei = next_switch_conn.send_command("show cdp nei " + mac_port + " det | inc IP", delay_factor=.1)
	
	cdp_nei_ip = re.findall(ip_regex, show_cdp_nei)
	# If cdp_nei_ip isn't empty, then assign it the first ip address found
	if cdp_nei_ip:
		cdp_nei_ip = cdp_nei_ip[0]
	return cdp_nei_ip


##########################################################################################################
#
#   GetVPCPLPort - returns the first Eth port that makes up the vPC Peer-Link port-channel
#
##########################################################################################################
def GetVPCPLPort(next_switch_conn):
	show_vpc_brief = next_switch_conn.send_command("show vpc brief | inc ^1", delay_factor=.1)
	
	# Find the first entry of the previous "show vpc brief" cmd output: this is the vpc-PL entry
	vpc_pl = re.search(r'1{1}\s*Po\d*', show_vpc_brief).group()
	
	# Find the vpc-PL port-channel
	mac_port = int_regexes[1].search(vpc_pl)
	mac_port_str = mac_port.group()
	
	# Get a list of physical interfaces that make up the vpc-PL PC
	etherchan_output = next_switch_conn.send_command("show port-channel summ | inc " + mac_port_str, delay_factor=.1)
	
	# Find the first physical interface that make up the vpc-PL PC and return it is a string
	mac_port = int_regexes[0].search(etherchan_output)
	mac_port_str = mac_port.group()
	return mac_port_str


##########################################################################################################
#
#  GetPortByMac - finds next switch port from the MAC address
#
##########################################################################################################
def GetPortByMac(device_type, next_switch_conn, mac):
	# find the port number of the mac address on IOS/XE/NXOS device
	if not device_type == 'cisco_xr':
		show_mac_table = next_switch_conn.send_command("show mac add add " + mac + " | inc " + mac, delay_factor=.1)
		
		# check if mac is found on Nexus vPC Peer-Link, if it is return the first member of the vpc pl port-channel
		mac_port_vpc = int_regexes[2].search(show_mac_table)
		if mac_port_vpc:
			return GetVPCPLPort(next_switch_conn)
	
		# check if mac is found on regular port
		mac_port = int_regexes[0].search(show_mac_table)
	
		# not found on a regular port, check etherchannels or port-channels
		if not mac_port:
			mac_port = int_regexes[1].search(show_mac_table)
			if mac_port:
				mac_port_str = mac_port.group()
				if device_type == 'cisco_nxos':
					etherchan_output = next_switch_conn.send_command("show port-channel summ | inc " + mac_port_str, delay_factor=.1)
				else:
					etherchan_output = next_switch_conn.send_command("show etherchan summ | inc " + mac_port_str, delay_factor=.1)
				mac_port = int_regexes[0].search(etherchan_output)
				
	# find the port number of the mac address on IOS XR
	else:
		show_mac_table = next_switch_conn.send_command("show arp | inc " + mac, delay_factor=.1)
		
		# check if mac is found on regular port
		mac_port = int_regexes[0].search(show_mac_table)
		
		# not found on a regular port, check bundle-ethers
		if not mac_port:
			mac_port = int_regexes[1].search(show_mac_table)
			mac_port_str = mac_port.group()
			show_int_bundle = next_switch_conn.send_command("show int " + mac_port_str + " | inc Active", delay_factor=.1)
			mac_port = int_regexes[0].search(show_int_bundle)
			
	# change mac_port from regex result to string
	return mac_port.group()


##########################################################################################################
#
#  GetMacFromIP - finds the MAC address of an IP address via ARP
#
##########################################################################################################
def GetMacFromIP(current_ip, device_type, core_switch_conn, username, password, current_vrf):
	# ping IP to scan and obtain MAC
	# NOTE: cmd syntax is slightly different depending on which Cisco OS is used
	if device_type == "cisco_nxos":
		core_switch_conn.send_command("ping " + current_ip + " " + vrf + " " + current_vrf + " count 2\n", delay_factor=.1)
	elif device_type == "cisco_xr":
		core_switch_conn.send_command("ping " + vrf + " " + current_vrf + " " + current_ip + " count 2\n", delay_factor=.1)
	else:
		core_switch_conn.send_command("ping " + vrf + " " + current_vrf + " " + current_ip + " repeat 2\n", delay_factor=.1)
		
	if device_type == "cisco_nxos":
		show_ip_arp = core_switch_conn.send_command("show ip arp " + current_ip + " " + vrf + " " + current_vrf + "\n", delay_factor=.1)
	elif device_type == "cisco_xr":
		show_ip_arp = core_switch_conn.send_command("show arp " + vrf + " " + current_vrf + " " + current_ip + "\n", delay_factor=.1)
	else:
		show_ip_arp = core_switch_conn.send_command("show ip arp " + vrf + " " + current_vrf  + " " + current_ip + "\n", delay_factor=.1)
	
	match_mac = mac_regex.search(show_ip_arp)

	if match_mac and match_mac.group() != '0000.0000.0000':
		return match_mac.group()
	else:
		return False
	

##########################################################################################################
#
#  TraceMac - Trace the MAC address through switches
#
##########################################################################################################
def TraceMac(mac, device_ip, dns_name, next_switch_conn, next_switch_ip, username, password):
	next_switch_hostname = next_switch_conn.find_prompt().rstrip("#>")
	next_switch_conn.enable()
	device_type = next_switch_conn.device_type

	# Find port that has MAC address
	port = GetPortByMac(device_type, next_switch_conn, mac)

	description = GetInterfaceDescription(next_switch_conn, port)
	interface_type, vlan = GetInterfaceMode(next_switch_conn, port)
	mac_count = GetMacCount(next_switch_conn, port)

	# See if port is another Cisco device, if it is then start tracing on that switch
	cdp_nei_ip = GetCDPNeighbor(device_type, next_switch_conn, port)
	next_switch_conn.disconnect()
	if cdp_nei_ip:
		sys.stderr = DevNull()
		try:
			cdp_nei_conn = RedispatchDeviceType(cdp_nei_ip, username, password)
			line = TraceMac(mac, device_ip, dns_name, cdp_nei_conn, cdp_nei_ip, username, password)
			cdp_nei_conn.disconnect()
		except:
			print("error:\n")
			print("Traced to CDP neighbor " + cdp_nei_ip + ", but could not SSH into it.\n")
			line = csv_line_template.format(device_ip, dns_name, mac, next_switch_hostname, next_switch_ip, port, description,
											interface_type, vlan, str(mac_count))
			cdp_nei_conn.disconnect()
			return line

	# Build line to print
	else:
		# Status output
		print("complete!\n")
		line = csv_line_template.format(device_ip, dns_name, mac, next_switch_hostname, next_switch_ip, port, description,
										interface_type, vlan, str(mac_count))
	
	return line


##########################################################################################################
#
#  TraceIPAddress - Trace the MAC address through switches
#
##########################################################################################################
def TraceIPAddress(ipaddress_ipcalc):
	# Get the MAC address from the core via ARP
	ipaddress = str(ipaddress_ipcalc)
	
	dns_name = "N/A"
	try:
		dns_name = gethostbyaddr(ipaddress)[0]
	except:
		pass
	print("\nTracing " + ipaddress + "...", end="")
	# if using script arguments
	if options:
		# connect to core device using vars from script
		core_switch_conn = RedispatchDeviceType(options.core_switch, options.username, password)
		device_type = core_switch_conn.device_type
		mac = GetMacFromIP(ipaddress, device_type, core_switch_conn, options.username, password, current_vrf)
	# if using prompts
	else:
		# connect to core device using vars from prompt
		core_switch_conn = RedispatchDeviceType(core_switch, username, password)
		device_type = core_switch_conn.device_type
		mac = GetMacFromIP(ipaddress, device_type, core_switch_conn, username, password, current_vrf)

	# If we can find the MAC start tracing
	if mac:
		# if using script arguments
		if options:
			line = TraceMac(mac, ipaddress, dns_name, core_switch_conn, options.core_switch, options.username, password)
		# if using prompts
		else:
			line = TraceMac(mac, ipaddress, dns_name, core_switch_conn, core_switch, username, password)
	# otherwise move on to the next IP address
	else:
		print("MAC not found in ARP")
		line = "{} Not Found\n".format(ipaddress)

	return line


##########################################################################################################
#
#  Main function
#
##########################################################################################################

def main():
	# if using script arguments
	if options:
		# if outputting to csv with arguments
		if options.filename:
			# Open the CSV and print the header
			csv_file = open(options.filename, "w")
			csv_file.write(csv_header)
			for ipaddress_ipcalc in ipcalc.Network(options.network_to_scan):
				line = TraceIPAddress(ipaddress_ipcalc)
				print(line)
				csv_file.write(line)
	# if outputting to csv with prompts
	elif filename:
		csv_file = open(filename, "w")
		csv_file.write(csv_header)
		# Loop over each IP in the network and trace
		for ipaddress_ipcalc in ipcalc.Network(network_to_scan):
			line = TraceIPAddress(ipaddress_ipcalc)
		#	print(csv_header + line)
			csv_file.write(line)
	# just print lines if not outputting to csv
	else:
		for ipaddress_ipcalc in ipcalc.Network(network_to_scan):
			line = TraceIPAddress(ipaddress_ipcalc)
			mac_found = mac_regex.search(line)
			if mac_found:
				values = line.split(',')
				headers = pprint_template.split(',')
				for i,header in enumerate(headers):
					headers[i] = header.format(values[i].strip('\n'))
				line = headers
				pprint(line,width=200)
			else:
				pprint(line.strip('\n'))


main()
