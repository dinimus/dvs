#!/usr/bin/env python3
import argparse, re, os, time, ldap3, json, urllib3, requests, sys, subprocess, shutil
from subprocess import Popen, PIPE
from argparse import RawTextHelpFormatter
import xml.etree.ElementTree as ET
from dns import reversename, resolver
from getpass import getpass
from requests.exceptions import HTTPError
try:
	from pymetasploit3.msfrpc import *
	# from pymetasploit3.msfconsole import MsfRpcConsole
except:
	print('You need to install Pymetasploit3:\npip3 install pymetasploit3')
	exit()
try:
	from templates_table_vuln import *
except:
	print("File 'templates_table_vuln.py' is not found")
	exit()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## GLOBAL VARS
confluence_site = SITE_CONFL
BASE_URL = "https://%s/confluence/rest/api/content" % confluence_site
VIEW_URL = "https://%s/confluence/pages/viewpage.action?pageId=" % confluence_site
width = shutil.get_terminal_size().columns
space_line = '>' + '-'*(width-1)
## END GLOBAL VARS

## prefix in name "d_" - it's a dict variable
## prefix in name "a_" - it's an array/list variable

## PARSING ARGS
def args_parse():
	parser = argparse.ArgumentParser(description='''\033[33m
			╭━━━┳╮╱╱╭┳━━━╮
			╰╮╭╮┃╰╮╭╯┃╭━╮┃
			╱┃┃┃┣╮┃┃╭┫╰━━╮
			╱┃┃┃┃┃╰╯┃╰━━╮┃
			╭╯╰╯┃╰╮╭╯┃╰━╯┃  
			╰━━━╯╱╰╯╱╰━━━╯ 
		╱Dangerous Vulnerabilities Scanner╱
\033[0m''', formatter_class=RawTextHelpFormatter, epilog='''Examples:
	Scan all and create pages in Confluence:
		./dvs.py scan -p Passwd -f ip.txt -c 'F7BCC4' -id 123123 -a

	Parse all:
		./dvs.py nmap -p Passwd -a nmap_all.xml

	Scan only SMB and RDP:
		./dvs.py scan -p Passwd -f ip.txt -s -r -ns 10.1.2.3
	''')

	subparsers = parser.add_subparsers(title='modes', dest='mode', description='available modes')

	s_parser = argparse.ArgumentParser(add_help=False)
	s_parser.add_argument('-c', '--cookie', dest='Cookie', metavar='cookie', type=str, help="Confluence's 'JSESSIONID' cookie value")
	s_parser.add_argument('-id', '--pid', dest='ParentPageID', metavar='ppid', type=int, help="Page's ID in the Confluence where page will be created")
	s_parser.add_argument('-ns', '--nameserver', type=str, default="1.1.1.1", help="IP address of nameserver. This is for checking Zerologon. Default is from \033[1m/etc/resolv.conf\033[0m")

	req_parser = s_parser.add_argument_group('required arguments')
	req_parser.add_argument('-p', '--pass', dest='PASS', required=True, metavar='strongP@sswd', type=str, help="Password of Metasploit RPC server. You can run it with 'msfrpcd -S -P yourpassword'")

	sub_pars_nmap = subparsers.add_parser('nmap', parents=[s_parser], help='Mode of parsing data from the Nmap.xml reports', formatter_class=RawTextHelpFormatter, epilog='''Examples:
	Parse all and create pages in Confluence:
		./dvs.py nmap -p Passwd -c 'F7BCC4' -id 123123 -a nmap_all.xml

	Only parse all:
		./dvs.py nmap -p Passwd -a nmap_all.xml -ns 10.1.2.3

	Parse only SMB and RDP:
		./dvs.py nmap -p Passwd -s nmap_445.xml -r nmap_rdp.xml
	''')
	sub_pars_nmap.add_argument('-s', dest='smb', metavar='smb.xml', type=str, help="Parse and check SMB")
	sub_pars_nmap.add_argument('-r', dest='rdp', metavar='rdp.xml', type=str, help="Parse and check RDP")
	sub_pars_nmap.add_argument('-cs', dest='csi', metavar='csi.xml', type=str, help="Parse and check CSI (Cisco Smart Install)")
	sub_pars_nmap.add_argument('-l', dest='ldap', metavar='ldap.xml', type=str, help="Parse and check LDAP")
	sub_pars_nmap.add_argument('-k', dest='kerb', metavar='kerb.xml', type=str, help="Parse and check Zerologon")
	sub_pars_nmap.add_argument('-i', dest='ipmi', metavar='ipmi.xml', type=str, help="Parse and check IPMI")
	sub_pars_nmap.add_argument('-sn', dest='snmp', metavar='snmp.xml', type=str, help="Parse and check SNMP")
	sub_pars_nmap.add_argument('-a', dest='all', metavar='all.xml', type=str, help="Parse and check all services")

	req_parser.add_argument('-f', '--file', required=True, dest='file_hosts', metavar='ip.txt', type=str, help="Target IP addresses file (.txt format)")
	
	sub_pars_scan = subparsers.add_parser('scan', parents=[s_parser], help='Mode of scanning hosts from the file', formatter_class=RawTextHelpFormatter, epilog='''Examples:
	Scan all and create pages in Confluence:
		./dvs.py scan -p Passwd -f ip.txt -c 'F7BCC4' -id 123123 -a -ns 10.1.2.3

	Only scan all:
		./dvs.py scan -p Passwd -f ip.txt -a

	Scan only SMB and RDP:
		./dvs.py scan -p Passwd -f ip.txt -s -r
	''')
	sub_pars_scan.add_argument('-s', dest='smb', action='store_true', help="Scan and check SMB")
	sub_pars_scan.add_argument('-r', dest='rdp', action='store_true', help="Scan and check RDP")
	sub_pars_scan.add_argument('-cs', dest='csi', action='store_true', help="Scan and check CSI (Cisco Smart Install)")
	sub_pars_scan.add_argument('-l', dest='ldap', action='store_true', help="Scan and check LDAP")
	sub_pars_scan.add_argument('-k', dest='kerb', action='store_true', help="Scan and check Zerologon")
	sub_pars_scan.add_argument('-i', dest='ipmi', action='store_true', help="Scan and check IPMI")
	sub_pars_scan.add_argument('-sn', dest='snmp', action='store_true', help="Scan and check SNMP")
	sub_pars_scan.add_argument('-a', dest='all', action='store_true', help="Scan and check all services")

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()

	return args

def nmap_parse(root, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp):
	a_del_ports = []
	for hostx in root.findall('host'):
		addr = hostx[1].get('addr')
		if addr not in d_nmap_hosts_with_ports.keys():
			d_nmap_hosts_with_ports[addr] = {}
		for portsx in hostx.iter('port'):
			portid = portsx.get('portid')
			if portsx not in d_nmap_hosts_with_ports[addr].keys():
				d_nmap_hosts_with_ports[addr][portid] = {}
			d_nmap_hosts_with_ports[addr][portid]['protocol'] = portsx.get('protocol')
			d_nmap_hosts_with_ports[addr][portid]['state'] = portsx[0].get('state')
			try:
				d_nmap_hosts_with_ports[addr][portid]['service'] = portsx[1].get('name')
			except:
				d_nmap_hosts_with_ports[addr][portid]['service'] = ''
			try:
				d_nmap_hosts_with_ports[addr][portid]['version'] = portsx[1].get('version')
			except:
				d_nmap_hosts_with_ports[addr][portid]['version'] = ''
			try:
				d_nmap_hosts_with_ports[addr][portid]['product'] = portsx[1].get('product')
			except:
				d_nmap_hosts_with_ports[addr][portid]['product'] = ''
			if portid == '445':
				a_ips_smb.append(addr)
				try:
					for script in hostx.iter('script'):
						if script.get('id') == 'smb-os-discovery':
							d_nmap_hosts_with_ports[addr][portid]['smb_os_discovery'] = script.get('output')
						elif script.get('id') == 'smb-security-mode':
							d_nmap_hosts_with_ports[addr][portid]['smb_security_mode'] = script.get('output')
						elif script.get('id') == 'smb-vuln-ms17-010':
							d_nmap_hosts_with_ports[addr][portid]['smb_vuln_ms17_010'] = script.get('output')
				except Exception as e:
					print("\033[1mError\033[0m: {}".format(e))
			elif portid == '3389':
				a_ips_rdp.append(addr)
				for script in hostx.iter('script'):
					if script.get('id') == 'rdp-ntlm-info':
						d_nmap_hosts_with_ports[addr][portid]['rdp_ntlm_info'] = script.get('output')
			elif portid == '4786':
				a_ips_csi.append(addr)
				d_nmap_hosts_with_ports[addr][portid]['csi'] = 'Cisco Smart Install?'
			elif portid == '623':
				a_ips_ipmi.append(addr)
				d_nmap_hosts_with_ports[addr][portid]['ipmi'] = 'IPMI'
			elif portid == '88':
				a_ips_kerb.append(addr)
				d_nmap_hosts_with_ports[addr][portid]['kerb'] = 'kerb'
			elif portid == '389':
				a_ips_ldap.append(addr)
				d_nmap_hosts_with_ports[addr][portid]['ldap'] = 'ldap'
			elif portid == '161':
				a_ips_snmp.append(addr)
				d_nmap_hosts_with_ports[addr][portid]['snmp'] = 'snmp'

	for ip in d_nmap_hosts_with_ports.keys():
		for port in d_nmap_hosts_with_ports[ip].keys():
			if d_nmap_hosts_with_ports[ip][port]['state'] != 'open':
				a_del_ports.append(port)
			else:
				continue
		for port in a_del_ports:
			del d_nmap_hosts_with_ports[ip][port]
		a_del_ports = []

	return d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp

def get_space_key(parent_page_id, headers):
	url = '{base}/{par_page_id}'.format(base = BASE_URL, par_page_id = parent_page_id)
	r = requests.get(url, headers = headers, verify=False)
	try:
		r.raise_for_status()
	except:
		print("\033[1m\033[91m(-)\033[0m Cookie or parent page's ID is wrong or page already exists. Check and try again.")
		exit()
	return r.json()['space']['key']
	print(r.json()['space']['key'])
	exit()

def create_new_page(space_key, page_title, par_page_id, cookie):
	data = {
		'type': 'page',
		'title': page_title,
		'ancestors': [{'id':par_page_id}],
		'space': {'key':space_key},
		'body': {
			'storage':{
				'representation':'storage',
			}
		}
	}
	url = '{base}'.format(base = BASE_URL)
	
	try:
		r = requests.post(url=url, data=json.dumps(data), headers = {'Cookie': cookie, 'Content-Type': 'application/json'}, verify=False)
		# Consider any status other than 2xx an error
		if not r.status_code // 100 == 2:
			print("\033[1mError\033[0m: Unexpected response {}".format(r))
		else:
			return r.json()['id']
	except requests.exceptions.RequestException as e:
		# A serious problem happened, like an SSLError or InvalidURL
		print("\033[1mError\033[0m: {}".format(e))

def get_page_info(pageid, headers):
	url = '{base}/{pageid}'.format(
		base = BASE_URL,
		pageid = pageid)
	r = None
	try:
		r = requests.get(url, headers = headers, verify=False)
		resp = r.json()
	except HTTPError as http_err:
		print('HTTP error occurred: %s' % http_err)
		exit()
	except Exception as err:
		print('Other error occurred: %s' % err)
		exit()

	if 'type' not in resp.keys():
		print('\033[1mError response\033[0m: %s' % resp)
		exit()

	return resp

def get_page_ancestors(pageid, headers):
	# Get basic page information plus the ancestors property
	url = '{base}/{pageid}?expand=ancestors'.format(
		base = BASE_URL,
		pageid = pageid)
	r = requests.get(url, headers = headers, verify=False)
	r.raise_for_status()
	return r.json()['ancestors']

def write_data(pageid, new_html, cookie, headers):
	# title = None
	info = get_page_info(pageid, headers)
	ver = int(info['version']['number']) + 1

	ancestors = get_page_ancestors(pageid, headers)

	anc = ancestors[-1]
	del anc['_links']
	del anc['_expandable']
	del anc['extensions']

	# if title is not None:
	#   info['title'] = title
	data = {
		'id' : str(pageid),
		'type' : 'page',
		'title' : info['title'],
		'version' : {'number' : ver},
		'ancestors' : [anc],
		'body' : {
			'storage' :
			{
				'representation' : 'storage',
				'value' : new_html,
			}
		}
	}

	data = json.dumps(data)
	url = '{base}/{pageid}'.format(base = BASE_URL, pageid = pageid)

	try:
		r = requests.put(
			url,
			data = data,
			headers = { 'Cookie': cookie, 'Content-Type' : 'application/json' },
			verify = False
		)
		resp = r.json()
	except HTTPError as http_err:
		print('HTTP error occurred: %s' % http_err)
	except Exception as err:
		print('Other error occurred: %s' % err)

	if r.status_code == 400:
		print('\033[1mError status code\033[0m = 400')
		print('\033[1mError message\033[0m: %s' % resp['message'])
		if 'Unexpected close tag </td>' in resp['message']:
			print('Sometimes it happens. Try again.')
		exit()

	print ("\033[1m\033[92m(+)\033[0m Wrote '%s' version %d" % (info['title'], ver))
	print ("\033[1m\033[92m(+)\033[0m URL: %s%s" % (VIEW_URL, pageid))

def args_parse_nmap(args_port, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp):
	with open(args_port, 'r') as file_par:
		tree = ET.parse(file_par)
	xml_root = tree.getroot()
	d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = nmap_parse(xml_root, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
	return d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp

def msf_scan(execmsf, a_rhosts, client):
	a_msf_out = []
	a_msf_targets = []
	execmsf['RHOSTS'] = ' '.join(a_rhosts)
	## Get required options that haven't been set yet
	# print(execmsf.missing_required)
	## Execute the module and return the output
	cid = client.consoles.console().cid
	msf_out = client.consoles.console(cid).run_module_with_output(execmsf)
	
	# print('"' + msf_out + '"')
	if '[+]' in msf_out:
		msf_out_lines = msf_out.rstrip().split('\n')
		# print(msf_out_lines)
		for line_msf in msf_out_lines:
			if '[+]' in line_msf:
				# print(line_msf)
				a_msf_out.append(line_msf)
				a_msf_targets.append(re.findall(r'[0-9]+(?:\.[0-9]+){3}', line_msf)[0])
	## for snmp:
	if '[*] System information:' in msf_out:
		a_msf_out = msf_out
	elif msf_out == 'VERBOSE => false\n':
		a_msf_out = 'Error'

	## for RDP NLA:
	if 'Detected RDP' in msf_out:
		a_msf_out = msf_out
	elif msf_out == 'VERBOSE => false\n':
		a_msf_out = 'Error'
	## write results into file: msf_out

	return a_msf_out, a_msf_targets

def nmap_scan(ip_list, port, scan, sudo_passwd):
	if scan == '-sT -sU':
		comm_nmap = '''screen -dmS nmapscan_all bash -c "nmap -Pn %s -iL %s -p%s -sV --open --script 'smb-os-discovery,smb-security-mode,smb-vuln-ms17-010,rdp-ntlm-info' -oX output_nmap_all.xml;"''' % (scan, ip_list, port)
		print("\033[1m\033[92m(+)\033[0m Nmap scan has been started. You can view the scan process in screen (as root) '\033[1msudo screen -r nmapscan_all\033[0m'")
	else:
		comm_nmap = '''screen -dmS nmapscan_%s bash -c "nmap -Pn %s -iL %s -p%s -sV --open --script 'smb-os-discovery,smb-security-mode,smb-vuln-ms17-010,rdp-ntlm-info' -oX output_nmap_%s.xml;"''' % (port, scan, ip_list, port, port)
		print("\033[1m\033[92m(+)\033[0m Nmap scan has been started. You can view the scan process in screen (as root) '\033[1msudo screen -r nmapscan_%s\033[0m'" % port)
	os.system('echo %s|sudo -S %s' % (sudo_passwd, comm_nmap))
	
	return True

def test_smb(a_ips_smb, client):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mMS17-010\033[0m...')
	exec_smb = client.modules.use('auxiliary', 'scanner/smb/smb_ms17_010')
	a_msf_out_smb, a_msf_targets_smb = msf_scan(exec_smb, a_ips_smb, client)

	if a_msf_out_smb != [] and a_msf_out_smb != 'Error':
		print("\033[1m\033[92m(+)\033[0m Vulnerable hosts:")
		print('\n'.join(a_msf_out_smb).replace('[+]', '\033[1m\033[92m[+]\033[0m'))
	elif a_msf_out_smb == 'Error':
		print("\033[90m(*)\033[0m \033[1mError\033[0m! Something wrong. Try again or check it manually.\nUse MSF module '\033[1mauxiliary/scanner/smb/smb_ms17_010\033[0m'")
	else:
		print("\033[1m\033[91m(-)\033[0m Hosts are \033[1mnot\033[0m vulnerable.")

	return a_msf_out_smb, a_msf_targets_smb

def test_rdp(a_ips_rdp, client):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mBlueKeep (CVE-2019-0708)\033[0m...')
	exec_rdp = client.modules.use('auxiliary', 'scanner/rdp/cve_2019_0708_bluekeep')
	a_msf_out_rdp, a_msf_targets_rdp = msf_scan(exec_rdp, a_ips_rdp, client)

	if a_msf_out_rdp != [] and a_msf_out_rdp != 'Error':
		print("\033[1m\033[92m(+)\033[0m Vulnerable hosts:")
		print('\n'.join(a_msf_out_rdp).replace('[+]', '\033[1m\033[92m[+]\033[0m'))
	elif a_msf_out_rdp == 'Error':
		print("\033[90m(*)\033[0m \033[1mError\033[0m! Something wrong. Try again or check it manually.\nUse MSF module '\033[1mauxiliary/scanner/rdp/cve_2019_0708_bluekeep\033[0m'")
	else:
		print("\033[1m\033[91m(-)\033[0m Hosts are \033[1mnot\033[0m vulnerable.")

	return a_msf_out_rdp, a_msf_targets_rdp

def test_rdp_nla(a_ips_rdp, client):
	# print('\n\033[90m(*)\033[0m Checking for \033[1mRDP NLA\033[0m...')
	exec_rdp = client.modules.use('auxiliary', 'scanner/rdp/rdp_scanner')
	a_msf_out_rdp2, a_msf_targets_rdp2 = msf_scan(exec_rdp, a_ips_rdp, client)
	a_msf_targets_rdp_nla = []
	a_msf_targets_rdp_not_nla = []
	a_msf_targets_rdp_nla_un = []
	a_msf_out_rdp_nla = []

	if 'Requires NLA:' in a_msf_out_rdp2:
		msf_out_lines2 = a_msf_out_rdp2.rstrip().split('\n')
		for line_nla in msf_out_lines2:
			if 'Requires NLA: Yes' in line_nla:
				a_msf_targets_rdp_nla.append(re.findall(r'[0-9]+(?:\.[0-9]+){3}', line_nla)[0])
			elif 'Requires NLA: No' in line_nla:
				a_msf_targets_rdp_not_nla.append(re.findall(r'[0-9]+(?:\.[0-9]+){3}', line_nla)[0])
			else:
				a_msf_out_rdp_nla.append(line_nla)
				try:
					a_msf_targets_rdp_nla_un.append(re.findall(r'[0-9]+(?:\.[0-9]+){3}', line_nla)[0])
				except:
					continue

	return a_msf_targets_rdp_nla, a_msf_targets_rdp_not_nla, a_msf_targets_rdp_nla_un, a_msf_out_rdp_nla

def test_csi(a_ips_csi, client):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mCisco Smart Install\033[0m...')
	exec_csi = client.modules.use('auxiliary', 'scanner/misc/cisco_smart_install')
	# exec_csi['LHOST'] = lhost_ip
	# exec_csi['ACTION'] = 'SCAN'
	a_msf_out_csi, a_msf_targets_csi = msf_scan(exec_csi, a_ips_csi, client)

	if a_msf_out_csi != [] and a_msf_out_csi != 'Error':
		print("\033[1m\033[92m(+)\033[0m Vulnerable hosts (use https://github.com/Sab0tag3d/SIET or MSF module '\033[1mauxiliary/scanner/misc/cisco_smart_install\033[0m' to exploit vuln):")
		print('\n'.join(a_msf_out_csi).replace('[+]', '\033[1m\033[92m[+]\033[0m'))
	elif a_msf_out_csi == 'Error':
		print("\033[90m(*)\033[0m \033[1mError\033[0m! Something wrong. Try again or check it manually.\nUse MSF module '\033[1mauxiliary/scanner/misc/cisco_smart_install\033[0m'")
	else:
		print("\033[1m\033[91m(-)\033[0m Hosts are \033[1mnot\033[0m vulnerable.")

	return a_msf_out_csi, a_msf_targets_csi

def test_ipmi(a_ips_ipmi, client, cwd):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mIPMI\033[0m (default hashes cracking is enabled - it can be slow)...')
	exec_ipmi = client.modules.use('auxiliary', 'scanner/ipmi/ipmi_dumphashes')
	exec_ipmi['OUTPUT_HASHCAT_FILE'] = '%s/output_hashes_ipmi.txt' % cwd
	# exec_ipmi['ACTION'] = 'SCAN'
	a_msf_out_ipmi, a_msf_targets_ipmi = msf_scan(exec_ipmi, a_ips_ipmi, client)

	if a_msf_out_ipmi != [] and a_msf_out_ipmi != 'Error':
		print("\033[1m\033[92m(+)\033[0m Vulnerable hosts:")
		print('\n'.join(a_msf_out_ipmi).replace('[+]', '\033[1m\033[92m[+]\033[0m'))
		print('\033[1m\033[92m(+)\033[0m Hashes have been saved to \033[1m%s/output_hashes_ipmi.txt\033[0m' % cwd)
	elif a_msf_out_ipmi == 'Error':
		print("\033[90m(*)\033[0m \033[1mError\033[0m! Something wrong. Try again or check it manually.\nUse MSF module '\033[1mauxiliary/scanner/ipmi/ipmi_dumphashes\033[0m'")
	else:
		print("\033[1m\033[91m(-)\033[0m Hosts are \033[1mnot\033[0m vulnerable.")

	return a_msf_out_ipmi, a_msf_targets_ipmi

def test_kerb(a_ips_kerb, client, cwd, ns_ip):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mZerologon\033[0m...')
	## get the nameserver IP
	with open('/etc/resolv.conf', 'r') as file_ns:
		for line in file_ns.read().splitlines():
			if 'nameserver ' in line:
				ns_ip = line.rstrip().split(' ')[1]
				break
	print('\033[90m(*)\033[0m Nameserver: %s' % ns_ip)
	resolver.nameservers = [ns_ip]

	a_dc_names_ip = []
	d_dc_names = {}
	for ipk in a_ips_kerb:
		a_reversed_dns = []
		rev_name = reversename.from_address(ipk)
		try:
			resolved = resolver.resolve(rev_name, 'PTR')
			# for r in range(0,len(resolved)):
			# 	a_reversed_dns.append(re.sub('\.$','', str(resolved[r])))
			# d_nmap_hosts_with_ports[ipk]['88']['hostname'] = ','.join(reversed_dns).replace(".,", ",")
			a_dc_names_ip.append('%s %s' % (str(resolved[0]).split('.')[0], ipk))
			d_dc_names[ipk] = str(resolved[0]).split('.')[0]
		except:
			# d_nmap_hosts_with_ports[ipk]['88']['hostname'] = ''
			print('\033[1mError\033[0m')

	zerol_name = '%s/CVE-2020-1472/zerologon_tester.py' % cwd
	if not os.path.isfile(zerol_name):
		print('\033[1m\033[91m(-)\033[0m You need to copy https://github.com/SecuraBV/CVE-2020-1472 to autotest Zerologon.')
	
	file_dc_name = '%s/output_dc.txt' % cwd
	file_out_zerol_name = '%s/output_zerologon.txt' % cwd
	file_zerol_script_name =  '%s/output_zerologon_scan.sh' % cwd
	if a_dc_names_ip != []:
		print('\033[90m(*)\033[0m List of DC names and IP addresses (also has been saved to \033[1m%s\033[0m):' % file_dc_name)
		print('\n'.join(a_dc_names_ip))
		with open(file_dc_name, 'w') as file_dc:
			file_dc.write('\n'.join(a_dc_names_ip))
		if os.path.isfile(zerol_name):
			comm_script = 'while read line; do echo -e "\\n$line:"; python3 ./CVE-2020-1472/zerologon_tester.py $line | grep -v "=\\|Performing authentication"; done < %s | tee %s' % (file_dc_name, file_out_zerol_name)
			with open(file_zerol_script_name, 'w') as file_zerol_script:
				file_zerol_script.write(comm_script)
			comm_zerologon_screen = 'screen -dmS zerologon bash -c "%s"' % file_zerol_script_name
			os.system(comm_zerologon_screen)
			print("\033[1m\033[92m(+)\033[0m Autoscan has been started. Use '\033[1mscreen -r zerologon\033[0m' to view the scan. The results will be saved to \033[1m%s\033[0m" % file_out_zerol_name)
			print('\033[1m\033[92m(+)\033[0m Or use script from \033[1m%s\033[0m' % file_zerol_script_name)
		else:
			print('\033[90m(*)\033[0m Use any tool to check them (e.g. https://github.com/SecuraBV/CVE-2020-1472)')
	else:
		print('\033[90m(*)\033[0m Use any tool to check this hosts (e.g. https://github.com/SecuraBV/CVE-2020-1472):')
		print('\n'.join(a_ips_kerb))

	return d_dc_names, file_dc_name, file_out_zerol_name

def test_ldap(a_ips_ldap, client, cwd):
	print(space_line)
	print('\033[90m(*)\033[0m Checking for \033[1mLDAP NULL base\033[0m vuln...')
	d_ldap_out = {}
	for ipl in a_ips_ldap:
		server = ldap3.Server(ipl, get_info = ldap3.ALL, port = 389, use_ssl = False)
		try:
			connection = ldap3.Connection(server)
			bind = connection.bind()
		except:
			print('\033[1m\033[91m(-)\033[0m LDAP (389/TCP) is unavailable. Check the 636/TCP manually if there is one.')
			continue
		if bind == True:
			server_info = json.loads(server.info.to_json())
			# server_schema = server.schema.to_json()
			# print(server_info)
			try:
				dc_entities = server_info['raw']['namingContexts'][0]
				# connection.search(dc_entities, '(objectclass=*)')
				# entries_root = json.loads(connection.entries.to_json())
				if connection.search(search_base=dc_entities, search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*'):
					entries_subtree = connection.response
					file_ldap_name = '%s/output_ldap_%s.json' % (cwd, ipl)
					print('\n\033[90m(*)\033[0m The host \033[1m%s\033[0m is most likely vulnerable. Check it manually. Entity of DC names: %s' % (ipl, str(dc_entities)))
					print("\033[1m\033[92m(+)\033[0m You can use ldapsearch to get more information:\nLDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '%s'" % (ipl, str(dc_entities)))
					print("\033[1m\033[92m(+)\033[0m Some parsed info has been saved to \033[1m%s\033[0m" % file_ldap_name)
					with open(file_ldap_name, 'w') as file_ldap:
						for item in entries_subtree:
							file_ldap.write('%s\n' % item)
					d_ldap_out[ipl] = "Most likely vuln. Check: LDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '%s'" % (ipl, str(dc_entities))
				else:
					print('\n\033[90m(*)\033[0m The host \033[1m%s\033[0m is most likely vulnerable. Check it manually. Entity of DC names: %s' % (ipl, str(dc_entities)))
					print("\033[1m\033[92m(+)\033[0m You can use ldapsearch to get more information:\nLDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '' -s base '(objectClass=*)' '*' +" % ipl)
					d_ldap_out[ipl] = "Most likely vuln. Check: LDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '' -s base '(objectClass=*)' '*' +" % ipl
			except:
				print('\n\033[90m(*)\033[0m Maybe the host \033[1m%s\033[0m is \033[1mnot\033[0m vulnerable. You can check it manually.' % ipl)
				print("\033[90m(*)\033[0m You can use ldapsearch to get more information:\nLDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '' -s base '(objectClass=*)' '*' +" % ipl)
				d_ldap_out[ipl] = "Maybe is NOT vuln. Check: LDAPTLS_REQCERT=never ldapsearch -H ldap://%s -x -v -b '' -s base '(objectClass=*)' '*' +" % ipl
		else:
			d_ldap_out[ipl] = "It's most likely NOT vulnerable"
			print('\033[1m\033[91m(-)\033[0m The host \033[1m%s\033[0m is most likely \033[1mnot\033[0m vulnerable.' % ipl)
			continue

	return d_ldap_out

def test_snmp(a_ips_snmp, client, cwd):
	print(space_line)
	print("\033[90m(*)\033[0m Checking for \033[1mSNMP (public)\033[0m. It can be slow if there are such hosts...")
	exec_snmp = client.modules.use('auxiliary', 'scanner/snmp/snmp_enum')
	exec_snmp['ShowProgress'] = False
	# exec_csi['LHOST'] = lhost_ip
	# exec_csi['ACTION'] = 'SCAN'
	a_msf_out_snmp, a_msf_targets_snmp = msf_scan(exec_snmp, a_ips_snmp, client)
	
	if a_msf_targets_snmp != [] and a_msf_out_snmp != 'Error':
		print('\033[1m\033[92m(+)\033[0m Vulnerable hosts:')
		print('\n'.join(a_msf_targets_snmp))
		file_snmp_name = '%s/output_snmp.txt' % cwd
		with open(file_snmp_name, 'w') as file_snmp:
			file_snmp.write(a_msf_out_snmp)
		print('\n\033[1m\033[92m(+)\033[0m Some parsed info has been saved to \033[1m%s\033[0m' % file_snmp_name)
	elif a_msf_out_snmp == 'Error':
		print("\033[90m(*)\033[0m \033[1mError\033[0m! Something wrong. Try again or check it manually.\nUse MSF module '\033[1mauxiliary/scanner/snmp/snmp_enum\033[0m'")
	else:
		print('\033[1m\033[91m(-)\033[0m Hosts are \033[1mnot\033[0m vulnerable.')

	return a_msf_out_snmp, a_msf_targets_snmp

def validate_pass(passwd):
	out_pass = b''
	comm_pass = "echo '%s' | sudo -S id" % passwd
	try:
		out_pass, err_pass = Popen(comm_pass, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()
	except:
		return False
	if b'(root)' in out_pass or b'uid=0' in out_pass:
		return True
	else:
		return False

def main():
	cwd = os.getcwd()
	a_test_list = []
	d_nmap_hosts_with_ports = {}
	a_ips_smb = []
	a_ips_rdp = []
	a_ips_csi = []
	a_ips_ipmi = []
	a_ips_kerb = []
	a_ips_ldap = []
	a_ips_snmp = []

	## Parsing:
	args = args_parse()
	passwd = args.PASS
	ns_ip = args.nameserver

	try:
		client = MsfRpcClient(passwd, port=55553, ssl=False)
	except:
		print("Password is wrong or MSF RPC server isn't running. Check and try again.\nYou can run the server with '\033[1msudo msfrpcd -P yourpassword -S\033[0m'")
		exit()

	if args.Cookie == None and args.ParentPageID == None:
		print('\033[90m(*)\033[0m Page in Confluence will \033[1mnot be\033[0m created')
	elif (args.Cookie != None and args.ParentPageID == None) or (args.Cookie == None and args.ParentPageID != None):
		print("\033[90m(*)\033[0m If you want to create page in Confluence you have to use parameters '\033[1m-c\033[0m' and '\033[1m-id\033[0m' at the same time!")
		exit()
	else:
		cookie = "JSESSIONID=%s" % args.Cookie
		parent_page_id = args.ParentPageID
		headers = {
		'Cookie': cookie,
		}

	if args.Cookie != None: # args.Cookie
		try:
			check_cookie = get_page_info(parent_page_id, headers)
		except Exception as err:
			print('\033[1m\033[91m(-)\033[0m \033[1mError\033[0m! Something wrong. Check the cookie and page id')
			print('Error: ', err)
			exit()
		if check_cookie['type'] == 'page':
			print('\033[90m(*)\033[0m Cookie is OK')
		else:
			print('\033[1m\033[91m(-)\033[0m \033[1mError\033[0m! Something wrong. Check the cookie and page id')
			print(check_cookie)
			exit()

	# Mode selection
	if args.mode == 'scan':
		print('\033[90m(*)\033[0m The \033[1mscan\033[0m mode is selected. Hosts will first be scanned using Nmap')
		if args.smb == False and args.rdp == False and args.csi == False and args.ldap == False and args.kerb == False and args.ipmi == False and args.snmp == False and args.all == False:
			print("\033[1m\033[91m(-)\033[0m Use \033[1mone type\033[0m of the scan [-s, -r, -cs, -l, -k, -i, -sn, -a]. See help using '\033[1m-h\033[0m'")
			exit()
		if (os.path.splitext(args.file_hosts)[1] != '.txt'):
			print ("It's not \033[1m.txt\033[0m file. Try again.")
			exit()
		else:
			ip_list = args.file_hosts

		pass_check = False
		while pass_check != True:
			try:
				sudo_passwd = getpass(prompt='\033[90m(*)\033[0m Please \033[1menter sudo password\033[0m: ')
				if validate_pass(sudo_passwd):
					pass_check = True
			except Exception as err:
				print('\033[1mError\033[0m: ', err)
				exit()
		
		if args.all:
			nmap_scan(ip_list,'T:445,3389,4786,389,88,U:623,161', '-sT -sU', sudo_passwd)
			a_test_list.append('all')
		else:
			if args.smb:
				nmap_scan(ip_list,'445', '-sT', sudo_passwd)
				a_test_list.append('445')
			if args.rdp:
				nmap_scan(ip_list,'3389', '-sT', sudo_passwd)
				a_test_list.append('3389')
			if args.csi:
				nmap_scan(ip_list,'4786', '-sT', sudo_passwd)
				a_test_list.append('4786')
			if args.ldap:
				nmap_scan(ip_list,'389', '-sT', sudo_passwd)
				a_test_list.append('389')
			if args.kerb:
				nmap_scan(ip_list,'88', '-sT', sudo_passwd)
				a_test_list.append('88')
			if args.ipmi:
				nmap_scan(ip_list,'623', '-sU', sudo_passwd)
				a_test_list.append('623')
			if args.snmp:
				nmap_scan(ip_list,'161', '-sU', sudo_passwd)
				a_test_list.append('161')

		## status:
		t = 1
		out_comm = ''
		comm_check = "screen -ls nmapscan_ | grep Detach | cut -d'.' -f 2- | cut -d'(' -f1"
		comm_check_sudo = 'echo "%s" |sudo -S %s' % (sudo_passwd, comm_check)
		out_comm, err_comm = Popen(comm_check_sudo, shell=True, stdout=PIPE, stderr=subprocess.DEVNULL).communicate()
		
		while out_comm.decode('UTF-8') != '':
			time.sleep(7)
			if args.Cookie != None: # args.Cookie
				check_cookie = get_page_info(parent_page_id, headers)
			t += 1
			out_comm, err_comm = Popen(comm_check_sudo, shell=True, stdout=PIPE, stderr=subprocess.DEVNULL).communicate()
			if t % 3 == 0:
				count = len((out_comm.decode('UTF-8').rstrip('\t\n').split('\n')))
				print('\033[90m(*)\033[0m \033[1m%s\033[0m scans left to complete' % str(count))
		
		out_comm, err_comm = Popen(comm_check_sudo, shell=True, stdout=PIPE, stderr=subprocess.DEVNULL).communicate()
		if out_comm.decode('UTF-8') != '':
			print('\033[90m(*)\033[0m Waiting for Nmap scanning is enabled (1 min)')
			time.sleep(60)
		print('\033[90m(*)\033[0m The scan completed')
		for port in a_test_list:
			filename = 'output_nmap_%s.xml' % port
			d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(filename, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
	
	elif args.mode == 'nmap':
		print('\033[90m(*)\033[0m The \033[1mnmap\033[0m mode is selected. Data will be parsed from Nmap files')
		if args.smb == None and args.rdp == None and args.csi == None and args.ldap == None and args.kerb == None and args.ipmi == None and args.snmp == None and args.all == None:
			print("\033[1m\033[91m(-)\033[0m Use \033[1mone type\033[0m of the Nmap parsing [-s, -r, -cs, -l, -k, -i, -sn, -a]. See help using '\033[1m-h\033[0m'")
			exit()
		if args.all != None:
			a_test_list.append('all')
			d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.all, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
		else:
			if args.smb != None:
				a_test_list.append('445')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.smb, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.rdp != None:
				a_test_list.append('3389')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.rdp, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.csi != None:
				a_test_list.append('4786')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.csi, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.ldap != None:
				a_test_list.append('389')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.ldap, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.kerb != None:
				a_test_list.append('88')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.kerb, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.ipmi != None:
				a_test_list.append('623')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.ipmi, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
			if args.snmp != None:
				a_test_list.append('161')
				d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp = args_parse_nmap(args.snmp, d_nmap_hosts_with_ports, a_ips_smb, a_ips_rdp, a_ips_csi, a_ips_ipmi, a_ips_kerb, a_ips_ldap, a_ips_snmp)
	## Parsing END

	# print(a_ips_smb)
	# print(a_ips_rdp)
	# print(a_ips_csi)
	# print(a_ips_ipmi)
	# print(a_ips_kerb)
	# print(a_ips_ldap)
	# print(a_ips_snmp)
	# print(d_nmap_hosts_with_ports)
	# print(a_test_list)

	## Test
	a_msf_out_smb, a_msf_targets_smb, a_msf_targets_rdp_nla, a_msf_targets_rdp_not_nla, a_msf_targets_rdp_nla_un, a_msf_out_rdp_nla, a_msf_out_rdp, a_msf_targets_rdp, a_msf_out_csi, a_msf_targets_csi, a_msf_out_ipmi, a_msf_targets_ipmi, a_msf_out_snmp, a_msf_targets_snmp = [], [], [], [], [], [], [], [], [], [], [], [], [], []
	d_dc_names, d_ldap_out = {}, {}
	file_dc_name, file_out_zerol_name = '', ''
	print('\n\033[90m(*)\033[0m Launch tests...')
	for test_type in a_test_list:
		if test_type == 'all':
			a_msf_out_smb, a_msf_targets_smb = test_smb(a_ips_smb, client)
			if args.Cookie != None:
				check_cookie = get_page_info(parent_page_id, headers)
			a_msf_targets_rdp_nla, a_msf_targets_rdp_not_nla, a_msf_targets_rdp_nla_un, a_msf_out_rdp_nla = test_rdp_nla(a_ips_rdp, client)
			a_msf_out_rdp, a_msf_targets_rdp = test_rdp(a_ips_rdp, client)
			a_msf_out_csi, a_msf_targets_csi = test_csi(a_ips_csi, client)
			d_dc_names, file_dc_name, file_out_zerol_name = test_kerb(a_ips_kerb, client, cwd, ns_ip)
			if args.Cookie != None:
				check_cookie = get_page_info(parent_page_id, headers)
			d_ldap_out = test_ldap(a_ips_ldap, client, cwd)
			if args.Cookie != None:
				check_cookie = get_page_info(parent_page_id, headers)
			a_msf_out_ipmi, a_msf_targets_ipmi = test_ipmi(a_ips_ipmi, client, cwd)
			if args.Cookie != None:
				check_cookie = get_page_info(parent_page_id, headers)
			a_msf_out_snmp, a_msf_targets_snmp = test_snmp(a_ips_snmp, client, cwd)
		else:
			if args.Cookie != None:
				check_cookie = get_page_info(parent_page_id, headers)
			if test_type == '445':
				a_msf_out_smb, a_msf_targets_smb = test_smb(a_ips_smb, client)
			if test_type == '3389':
				a_msf_targets_rdp_nla, a_msf_targets_rdp_not_nla, a_msf_targets_rdp_nla_un, a_msf_out_rdp_nla = test_rdp_nla(a_ips_rdp, client)
				a_msf_out_rdp, a_msf_targets_rdp = test_rdp(a_ips_rdp, client)
			if test_type == '4786':
				a_msf_out_csi, a_msf_targets_csi = test_csi(a_ips_csi, client)
			if test_type == '88':
				d_dc_names, file_dc_name, file_out_zerol_name = test_kerb(a_ips_kerb, client, cwd, ns_ip)
			if test_type == '389':
				d_ldap_out = test_ldap(a_ips_ldap, client, cwd)
				if args.Cookie != None:
					check_cookie = get_page_info(parent_page_id, headers)
			if test_type == '623':
				a_msf_out_ipmi, a_msf_targets_ipmi = test_ipmi(a_ips_ipmi, client, cwd)
				if args.Cookie != None:
					check_cookie = get_page_info(parent_page_id, headers)
			if test_type == '161':
				a_msf_out_snmp, a_msf_targets_snmp = test_snmp(a_ips_snmp, client, cwd)
				if args.Cookie != None:
					check_cookie = get_page_info(parent_page_id, headers)

	# print(a_msf_out_smb)
	# print(a_msf_targets_smb)
	# print(a_msf_out_rdp)
	# print(a_msf_targets_rdp)
	# print(a_msf_out_csi)
	# print(a_msf_targets_csi)
	# print(file_dc_name)
	# print(file_out_zerol_name)
	# print(d_ldap_out)
	# print(a_msf_out_ipmi)
	# print(a_msf_targets_ipmi)
	# print(a_msf_out_snmp)
	# print(a_msf_targets_snmp)

	## Create Confluence pages
	if args.Cookie != None:
		print(space_line)
		print("\033[90m(*)\033[0m Pages creating...")
		space_key = get_space_key(parent_page_id, headers)
		org_name_title = get_page_info(parent_page_id, headers)['title']
		try:
			org_name = "%s _Del_It" % org_name_title.split("Топ уязвимостей ")[1]
		except:
			try:
				org_name = "%s _Del_It" % org_name_title.rsplit(' ',1)[1]
			except:
				org_name = "ORG_NAME"

		all_rows_smb = ''
		all_rows_rdp = ''
		all_rows_csi = ''
		all_rows_ipmi = ''
		all_rows_kerb = ''
		all_rows_ldap = ''
		all_rows_snmp = ''

		s, r, c, i, k, l, sp = 1, 1, 1, 1, 1, 1, 1
		for ipc in d_nmap_hosts_with_ports.keys():
			row_temp_smb = ''
			row_temp_rdp = ''
			row_temp_csi = ''
			row_temp_ipmi = ''
			row_temp_kerb = ''
			row_temp_ldap = ''
			row_temp_snmp = ''
			open_ports = []
			port_services = []
			for portc in d_nmap_hosts_with_ports[ipc].keys():
				if portc == '445':
					row_temp_smb = TABLE_VULN_ROW_SMB_TEMP.replace('SMB_NUM', str(s)).replace('SMB_IP', ipc).replace('SMB_SIGN', d_nmap_hosts_with_ports[ipc][portc]['smb_security_mode'])
					s+=1
					if ipc in a_msf_targets_smb:
						row_temp_smb = row_temp_smb.replace('SMB_VULN', PIC_TICK)
					else:
						row_temp_smb = row_temp_smb.replace('SMB_VULN', '–')
					if 'smb_os_discovery' in d_nmap_hosts_with_ports[ipc][portc].keys():
						row_temp_smb = row_temp_smb.replace('SMB_OS', d_nmap_hosts_with_ports[ipc][portc]['smb_os_discovery'])
					else:
						row_temp_smb = row_temp_smb.replace('SMB_OS', '%s %s' % (d_nmap_hosts_with_ports[ipc][portc]['product'], d_nmap_hosts_with_ports[ipc][portc]['version'])).replace(' None', '')
				elif portc == '3389':
					row_temp_rdp = TABLE_VULN_ROW_RDP_TEMP.replace('RDP_NUM', str(r)).replace('RDP_IP', ipc)
					r+=1
					if ipc in a_msf_targets_rdp:
						row_temp_rdp = row_temp_rdp.replace('RDP_VULN', PIC_TICK)
					else:
						row_temp_rdp = row_temp_rdp.replace('RDP_VULN', '–')
					if 'rdp_ntlm_info' in d_nmap_hosts_with_ports[ipc][portc].keys():
						row_temp_rdp = row_temp_rdp.replace('RDP_INFO', d_nmap_hosts_with_ports[ipc][portc]['rdp_ntlm_info'])
					else:
						row_temp_rdp = row_temp_rdp.replace('RDP_INFO', '–')
					if ipc in a_msf_targets_rdp_nla:
						row_temp_rdp = row_temp_rdp.replace('RDP_NLA', 'Yes')
					elif ipc in a_msf_targets_rdp_not_nla:
						row_temp_rdp = row_temp_rdp.replace('RDP_NLA', 'No')
					elif ipc in a_msf_targets_rdp_nla_un:
						row_temp_rdp = row_temp_rdp.replace('RDP_NLA', '?')
				elif portc == '4786':
					row_temp_csi = TABLE_VULN_ROW_CSI_TEMP.replace('CSI_NUM', str(c)).replace('CSI_IP', ipc)
					c+=1
					if ipc in a_msf_targets_csi:
						row_temp_csi = row_temp_csi.replace('CSI_VULN', PIC_TICK)
					else:
						row_temp_csi = row_temp_csi.replace('CSI_VULN', '–')
				elif portc == '623':
					row_temp_ipmi = TABLE_VULN_ROW_IPMI_TEMP.replace('IPMI_NUM', str(i)).replace('IPMI_IP', ipc)
					i+=1
					if ipc in a_msf_targets_ipmi:
						row_temp_ipmi = row_temp_ipmi.replace('IPMI_VULN', PIC_TICK)
						for line_ipmi in a_msf_out_ipmi:
							if ipc in line_ipmi:
								row_temp_ipmi = row_temp_ipmi.replace('IPMI_HASH', line_ipmi[line_ipmi.find('Hash found')+12:])
					else:
						row_temp_ipmi = row_temp_ipmi.replace('IPMI_VULN', '–')
						row_temp_ipmi = row_temp_ipmi.replace('IPMI_HASH', '–')
				elif portc == '88':
					row_temp_kerb = TABLE_VULN_ROW_KERB_TEMP.replace('KERB_NUM', str(k)).replace('KERB_IP', ipc).replace('KERB_NAME', d_dc_names[ipc]).replace('KERB_VULN', '%s Check it' % PIC_WARNING)
					k+=1
				elif portc == '389':
					row_temp_ldap = TABLE_VULN_ROW_LDAP_TEMP.replace('LDAP_NUM', str(l)).replace('LDAP_IP', ipc)
					l+=1
					if ipc in d_ldap_out.keys():
						row_temp_ldap = row_temp_ldap.replace('LDAP_VULN', d_ldap_out[ipc])
					else:
						row_temp_ldap = row_temp_ldap.replace('LDAP_VULN', '–')
				elif portc == '161':
					row_temp_snmp = TABLE_VULN_ROW_SNMP_TEMP.replace('SNMP_NUM', str(sp)).replace('SNMP_IP', ipc)
					sp+=1
					if ipc in a_msf_targets_snmp:
						row_temp_snmp = row_temp_snmp.replace('SNMP_INFO', "%s 'public' is enabled" % PIC_TICK)
					else:
						row_temp_snmp = row_temp_snmp.replace('SNMP_INFO', '–')

			all_rows_smb = all_rows_smb + row_temp_smb
			all_rows_rdp = all_rows_rdp + row_temp_rdp
			all_rows_csi = all_rows_csi + row_temp_csi
			all_rows_ipmi = all_rows_ipmi + row_temp_ipmi
			all_rows_kerb = all_rows_kerb + row_temp_kerb
			all_rows_ldap = all_rows_ldap + row_temp_ldap
			all_rows_snmp = all_rows_snmp + row_temp_snmp

		org_name_title_link = org_name_title.replace(' ', '')
		new_html_table_vuln = TABLE_VULN.replace('PAGE_TITLE', org_name_title_link)
		if (a_msf_targets_smb != []) or (a_ips_smb != [] and a_msf_targets_smb == []):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_SMB', all_rows_smb).replace('SMB_IP_LIST', '\n'.join(a_msf_targets_smb)).replace('SMB_IP_ALL', '\n'.join(a_ips_smb))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_SMB', TABLE_VULN_ROW_NOT_VULN_5).replace('SMB_IP_LIST', '').replace('SMB_IP_ALL', '')
		if (a_msf_targets_rdp != []) or (a_ips_rdp != [] and a_msf_targets_rdp == []):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_RDP', all_rows_rdp).replace('RDP_IP_LIST', '\n'.join(a_msf_targets_rdp)).replace('RDP_IP_ALL', '\n'.join(a_ips_rdp))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_RDP', TABLE_VULN_ROW_NOT_VULN_5).replace('RDP_IP_LIST', '').replace('RDP_IP_ALL', '')
		if (a_msf_targets_csi != []) or (a_ips_csi != [] and a_msf_targets_csi == []):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_CSI', all_rows_csi).replace('CSI_IP_LIST', '\n'.join(a_msf_targets_csi)).replace('CSI_IP_ALL', '\n'.join(a_ips_csi))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_CSI', TABLE_VULN_ROW_NOT_VULN_4).replace('CSI_IP_LIST', '').replace('CSI_IP_ALL', '')
		if (a_msf_targets_ipmi != []) or (a_ips_ipmi != [] and a_msf_targets_ipmi == []):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_IPMI', all_rows_ipmi).replace('IPMI_IP_LIST', '\n'.join(a_msf_targets_ipmi)).replace('IPMI_IP_ALL', '\n'.join(a_ips_ipmi))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_IPMI', TABLE_VULN_ROW_NOT_VULN_4).replace('IPMI_IP_LIST', '').replace('IPMI_IP_ALL', '')
		if (d_dc_names != {}) or (a_ips_kerb != [] and d_dc_names == {}):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_KERB', all_rows_kerb).replace('KERB_IP_LIST', '\n'.join('%s %s' % (value, key) for key, value in d_dc_names.items())).replace('KERB_IP_ALL', '\n'.join(a_ips_kerb))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_KERB', TABLE_VULN_ROW_NOT_VULN_4).replace('KERB_IP_LIST', '').replace('KERB_IP_ALL', '')
		if (d_ldap_out != {}) or (a_ips_ldap != [] and d_ldap_out == {}):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_LDAP', all_rows_ldap).replace('LDAP_IP_LIST', '\n'.join(d_ldap_out.keys())).replace('LDAP_IP_ALL', '\n'.join(a_ips_ldap))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_LDAP', TABLE_VULN_ROW_NOT_VULN_3).replace('LDAP_IP_LIST', '').replace('LDAP_IP_ALL', '')
		if (a_msf_targets_snmp != []) or (a_ips_snmp != [] and a_msf_targets_snmp == []):
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_SNMP', all_rows_snmp).replace('SNMP_IP_LIST', '\n'.join(a_msf_targets_snmp)).replace('SNMP_IP_ALL', '\n'.join(a_ips_snmp))
		else:
			new_html_table_vuln = new_html_table_vuln.replace('TABLE_VULN_ROW_SNMP', TABLE_VULN_ROW_NOT_VULN_3).replace('SNMP_IP_LIST', '').replace('SNMP_IP_ALL', '')

		# print(new_html_table_vuln)
		write_data(parent_page_id, new_html_table_vuln, cookie, headers)

if __name__ == "__main__" : main()
