TABLE_VULN = '''<br />
<div class="toc-macro client-side-toc-macro  conf-macro output-block hidden-outline" data-headerelements="H1,H2,H3,H4,H5,H6,H7" data-hasbody="false" data-macro-name="toc">
	<ul style="">
		<li><span class="toc-item-body" data-outline="1"><a href="#id-PAGE_TITLE-SMB(445/tcp)" class="toc-link">SMB (445/tcp)</a></span></li>
		<li><span class="toc-item-body" data-outline="2"><a href="#id-PAGE_TITLE-RDP(3389/tcp)" class="toc-link">RDP (3389/tcp)</a></span></li>
		<li><span class="toc-item-body" data-outline="3"><a href="#id-PAGE_TITLE-CiscoSmartInstall(4786/tcp)" class="toc-link">Cisco Smart Install (4786/tcp)</a></span></li>
		<li><span class="toc-item-body" data-outline="4"><a href="#id-PAGE_TITLE-IPMI(623/udp)" class="toc-link">IPMI (623/udp)</a></span></li>
		<li><span class="toc-item-body" data-outline="5"><a href="#id-PAGE_TITLE-Kerberos(88/tcp)" class="toc-link">Kerberos (88/tcp)</a></span></li>
		<li><span class="toc-item-body" data-outline="6"><a href="#id-PAGE_TITLE-LDAP(389/tcp)" class="toc-link">LDAP (389/tcp)</a></span></li>
		<li><span class="toc-item-body" data-outline="7"><a href="#id-PAGE_TITLE-SNMP(161/udp)" class="toc-link">SNMP (161/udp)</a></span></li>
	</ul>
</div>
<h2>SMB (445/tcp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Info</th>
			<th class="confluenceTh">MS17-010</th>
			<th class="confluenceTh">SMB sign</th>
		</tr>
        TABLE_VULN_ROW_SMB
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[SMB_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[SMB_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">RDP (3389/tcp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Info</th>
			<th class="confluenceTh">Bluekeep</th>
			<th class="confluenceTh">Requires NLA</th>
		</tr>
        TABLE_VULN_ROW_RDP
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[RDP_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[RDP_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">Cisco Smart Install (4786/tcp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Vulnerable</th>
			<th class="confluenceTh">Creds</th>
		</tr>
		TABLE_VULN_ROW_CSI
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[CSI_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[CSI_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">IPMI (623/udp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Vulns</th>
			<th class="confluenceTh">Creds</th>
		</tr>
		TABLE_VULN_ROW_IPMI
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[IPMI_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[IPMI_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">Kerberos (88/tcp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Name</th>
			<th class="confluenceTh">Zerologon</th>
		</tr>
		TABLE_VULN_ROW_KERB
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[KERB_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[KERB_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">LDAP (389/tcp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Info</th>
		</tr>
		TABLE_VULN_ROW_LDAP
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[LDAP_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[LDAP_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>

<h2 class="auto-cursor-target">SNMP (161/udp)</h2>
<table class="confluenceTable">
	<colgroup><col /><col /><col />
	</colgroup>
	<tbody>
		<tr>
			<th class="confluenceTh">#</th>
			<th class="confluenceTh">IP</th>
			<th class="confluenceTh">Info</th>
		</tr>
		TABLE_VULN_ROW_SNMP
	</tbody>
</table>

<ac:structured-macro ac:name="expand">
	<ac:parameter ac:name="title">List of IP...</ac:parameter>
	<ac:rich-text-body>
		<p>All tested IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[SNMP_IP_ALL]]>
			</ac:plain-text-body>
		</ac:structured-macro>
		<p>Vulnerable IP:</p>
		<ac:structured-macro ac:name="code" ac:schema-version="1" ac:body-type="PLAIN_TEXT">
			<ac:parameter ac:name="collapse">false</ac:parameter>
			<ac:parameter ac:name="linenumbers">true</ac:parameter>
			<ac:plain-text-body>
				<![CDATA[SNMP_IP_LIST]]>
			</ac:plain-text-body>
		</ac:structured-macro>
	</ac:rich-text-body>
</ac:structured-macro>
<br />'''

TABLE_VULN_ROW_SMB_TEMP = '''<tr>
	<td class="confluenceTd">SMB_NUM</td>
	<td class="confluenceTd">SMB_IP</td>
	<td class="confluenceTd">SMB_OS</td>
	<td class="confluenceTd">SMB_VULN</td>
	<td class="confluenceTd">SMB_SIGN</td>
</tr>'''

TABLE_VULN_ROW_RDP_TEMP = '''<tr>
	<td class="confluenceTd">RDP_NUM</td>
	<td class="confluenceTd">RDP_IP</td>
	<td class="confluenceTd">RDP_INFO</td>
	<td class="confluenceTd">RDP_VULN</td>
	<td class="confluenceTd">RDP_NLA</td>
</tr>'''

TABLE_VULN_ROW_CSI_TEMP = '''<tr>
	<td class="confluenceTd">CSI_NUM</td>
	<td class="confluenceTd">CSI_IP</td>
	<td class="confluenceTd">CSI_VULN</td>
	<td class="confluenceTd">add</td>
</tr>'''

TABLE_VULN_ROW_IPMI_TEMP = '''<tr>
	<td class="confluenceTd">IPMI_NUM</td>
	<td class="confluenceTd">IPMI_IP</td>
	<td class="confluenceTd">IPMI_VULN</td>
	<td class="confluenceTd">IPMI_HASH</td>
</tr>'''

TABLE_VULN_ROW_KERB_TEMP = '''<tr>
	<td class="confluenceTd">KERB_NUM</td>
	<td class="confluenceTd">KERB_IP</td>
	<td class="confluenceTd">KERB_NAME</td>
	<td class="confluenceTd">KERB_VULN</td>
</tr>'''

TABLE_VULN_ROW_LDAP_TEMP = '''<tr>
	<td class="confluenceTd">LDAP_NUM</td>
	<td class="confluenceTd">LDAP_IP</td>
	<td class="confluenceTd">LDAP_VULN</td>
</tr>'''

TABLE_VULN_ROW_SNMP_TEMP = '''<tr>
	<td class="confluenceTd">SNMP_NUM</td>
	<td class="confluenceTd">SNMP_IP</td>
	<td class="confluenceTd">SNMP_INFO</td>
</tr>'''

TABLE_VULN_ROW_NOT_VULN_5 = '''<tr>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
</tr>'''

TABLE_VULN_ROW_NOT_VULN_4 = '''<tr>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
</tr>'''

TABLE_VULN_ROW_NOT_VULN_3 = '''<tr>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
	<td class="confluenceTd">-</td>
</tr>'''

PIC_WARNING = '''<ac:emoticon ac:name="warning" />'''
PIC_TICK = '''<ac:emoticon ac:name="tick" />'''
PIC_INFO = '''<ac:emoticon ac:name="information" />'''
PIC_CROSS = '''<ac:emoticon ac:name="cross" />'''
