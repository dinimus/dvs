# DVS
**Dangerous Vulnerabilities Scanner** - scanner for finding dangerous and common vulnerabilities (more applicable on intranet).  
The scanner checks:
- SMB (MS17-010)
- RDP (Bluekeep, NLA)
- Cisco Smart Install
- IPMI (hash discloser)
- DC (Zerologon)
- LDAP (NULL Base)
- SNMP ('public' community name)  
  
Script from the https://github.com/Kecatoca/Zerologon_test is used to check the Zerologon.

## Install
```
git clone https://github.com/dinimus/dvs.git
cd dvs
pip3 install -r requirements.txt
```
*templates_table_vuln.py* - page's template in Confluence. You can change it.  
  
:warning:  
If you need to create page in Confluence, you need to change the string 'SITE_CONFL' to your Confluence's hostname/IP in dvs.py.  

### Tools
Also you need:
- Metasploit RPC Server (https://www.metasploit.com/)
- Zerologon tester (https://github.com/Kecatoca/Zerologon_test), already downloaded  
  
For start Metasploit RPC Server:
```
msfrpcd -S -P yourpassword
```
Installing zerologon tester (requires Python 3.7 or higher):
```
cd dvs/CVE-2020-1472
pip install -r requirements.txt
pip install impacket
```

# Help
```
modes:
  available modes
  {nmap,scan}
    nmap       Mode of parsing data from the Nmap.xml reports
    scan       Mode of scanning hosts from the file
 
Help for 'nmap':
optional arguments:
  -h, --help            show this help message and exit
  -c cookie, --cookie cookie
                        Confluence's 'JSESSIONID' cookie value
  -id ppid, --pid ppid  Parent page's ID in Confluence where page will be created
  -ns NAMESERVER, --nameserver NAMESERVER
                        IP address of nameserver. This is for checking Zerologon. Default is from /etc/resolv.conf
  -s smb.xml            Parse and check SMB
  -r rdp.xml            Parse and check RDP
  -cs csi.xml           Parse and check CSI (Cisco Smart Install)
  -l ldap.xml           Parse and check LDAP
  -k kerb.xml           Parse and check Zerologon
  -i ipmi.xml           Parse and check IPMI
  -sn snmp.xml          Parse and check SNMP
  -a all.xml            Parse and check all services
 
required arguments:
  -p strongP@sswd, --pass strongP@sswd
                        Password of Metasploit RPC server. You can run it with 'msfrpcd -S -P yourpassword'
 
Help for 'scan':
optional arguments:
  -h, --help            show this help message and exit
  -c cookie, --cookie cookie
                        Confluence's 'JSESSIONID' cookie value
  -id ppid, --pid ppid  Page's ID in Confluence where page will be created
  -ns NAMESERVER, --nameserver NAMESERVER
                        IP address of nameserver. This is for checking Zerologon. Default is from /etc/resolv.conf
  -s                    Scan and check SMB
  -r                    Scan and check RDP
  -cs                   Scan and check CSI (Cisco Smart Install)
  -l                    Scan and check LDAP
  -k                    Scan and check Zerologon
  -i                    Scan and check IPMI
  -sn                   Scan and check SNMP
  -a                    Scan and check all services
 
required arguments:
  -p strongP@sswd, --pass strongP@sswd
                        Password of Metasploit RPC server. You can run it with 'msfrpcd -S -P yourpassword'
  -f ip.txt, --file ip.txt
                        Target IP addresses file (.txt format)
```

# Examples
```
./dvs.py scan [-h] [-c cookie] [-id ppid] [-ns NAMESERVER] -p strongP@sswd -f ip.txt [-s] [-r] [-cs] [-l] [-k] [-i] [-sn] [-a]
./dvs.py nmap [-h] [-c cookie] [-id ppid] [-ns NAMESERVER] -p strongP@sswd [-s smb.xml] [-r rdp.xml] [-cs csi.xml] [-l ldap.xml] [-k kerb.xml] [-i ipmi.xml] [-sn snmp.xml] [-a all.xml]
 
Parse all and create pages in Confluence:
        ./dvs.py nmap -p Passwd -c 'F7BCC4' -id 123123 -a nmap_all.xml

Only parse all:
        ./dvs.py nmap -p Passwd -a nmap_all.xml -ns 10.1.2.3

Parse only SMB and RDP:
        ./dvs.py nmap -p Passwd -s nmap_445.xml -r nmap_rdp.xml

Scan all and create pages in Confluence:
        ./dvs.py scan -p Passwd -f ip.txt -c 'F7BCC4' -id 123123 -a -ns 10.1.2.3

Only scan all:
        ./dvs.py scan -p Passwd -f ip.txt -a

Scan only SMB and RDP:
        ./dvs.py scan -p Passwd -f ip.txt -s -r
```
