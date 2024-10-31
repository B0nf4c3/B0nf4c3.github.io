---
title: TryHackMe - Psycho_Break
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe]
tags: [tryhackme, linux, nmap, privesc, http, gobuster, ssh]

image:
    path: /assets/img/try%20hack%20me%20/Easy/Psycho_Break/0.jpeg
    alt: Psycho_Break
---

# Psycho_Break


# Recon
- Run nmap scan to discover the open ports
- Run gobuster to discover the directories

# nmap

## Command
```sh
sudo nmap -sS -sC -sV -A -v 10.10.240.78
```
## Nmap Result
```sh
PORT STATE SERVICE VERSION
21/tcp open ftp ProFTPD 1.3.5a
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 44:2f:fb:3b:f3:95:c3:c6:df:31:d6:e0:9e:99:92:42 (RSA)
| 256 92:24:36:91:7a:db:62:d2:b9:bb:43:eb:58:9b:50:14 (ECDSA)
|_ 256 34:04:df:13:54:21:8d:37:7f:f8:0a:65:93:47:75:d0 (ED25519)
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome To Becon Mental Hospital
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```
## discovered 3 open ports
that is :
- 21 ftp
- 22 ssh
- 80 http
## OS
22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)  
its `ubuntu`


# web

## web page
`http://10.10.240.78`

To Do List
----------------------------------------------
- View the site
- source code
- Robots.txt
- gobuster


```sh
gobuster dir -u http://10.10.201.211 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```sh
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css
(Status: 301) [Size: 312] [--> http://10.10.201.211/css/]
/js
(Status: 301) [Size: 311] [--> http://10.10.201.211/js/]
Progress: 5126 / 220561 (2.32%)[ERROR] Get "http://10.10.201.211/487": context deadline exceeded
(Client.Timeout exceeded while awaiting headers)
Progress: 8135 / 220561 (3.69%)[ERROR] Get "http://10.10.201.211/1375": context deadline exceeded
(Client.Timeout exceeded while awaiting headers)
Progress: 14885 / 220561 (6.75%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 14891 / 220561 (6.75%)

```
Nothing much so i just ignored the scan results and proceeded with other tests

## SourceCode
From `http://10.10.201.211/` i get this on the source code  
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/1.png)

Visited the site and got some interesting things.  

Websurfing
site `http://10.10.240.78/sadistRoom`

sadistRoom
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/2.png)

After coping the key immediately i pressed ok i was redirected to another page that warned me to enter the key fast before sebastian died.  
Entering The key i find Sebastian hiding in a Locker room.  
I Wander what's next???  


Locker Room
---------------------------------------------------------------------------------
Sebastian is hiding inside a locker to make it harder for the sadist to find him.  
While Sebastian was inside the locker he found a note.  
That looks like a map of some kind.  
Decode this piece of text `Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv` and get the key to access the map.  
Decoding i get `Grant_me_access_to_the_map_please`  
The map is in `http://10.10.240.78/map.php`  



map.php
------------------------------------------------------------------------------------
Here is the map
1. Sadist Room
2. Locker Room
3. Safe Heaven
4. The Abandoned Room
We have visited the first two rooms ,let's head direct to the safe house


Safe Heaven
-------------------------------------------------------------------------------------
Looking around we find some pics and some text but nothing useful.  
I head direct to the source code.  
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/3.png)
Wander what it means so i just run a normal gobuster to see is there is any sub-directories.  

```sh
gobuster dir -u http://10.10.240.78/SafeHeaven/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Looks like we have a directory named < /keeper >
`http://10.10.240.78/SafeHeaven/keeper`


SafeHeaven/keeper
--------------------------------------------------------------------------------------
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/4.png)

Had to rush my osint skills since the timer was damn! on  
steps 
1. save the image onto my machine
2. Enter Google Images
3. upload the image

To get = St. Augustine Lighthouse
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/5.png)

The Abandoned Room
--------------------------------------------------------------------------------------
We first enter the keeper's key to access the room.  
Sebastian wants to do further investigation .  
Okay let's help him.  

The room has spiderlady whom we have to run from before she catches our hero.  
The source code says something to do with `shell`.  

So i added ?shell=ls to the url .  
And it works so i add “ls .. ” to view to directories before this one.  
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/6.png)

Grabbed the first one coz time was almost over.  
And got this:  
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/7.png)

From `you_made_it.txt` we get: 
`You made it. Escaping from Laura is not easy, good job ....`
From the `helpme.zip`
1. First unzip it.
2. cat the txt file
```sh
cat helpme.txt
From Joseph,
	Who ever sees this message "HELP Me". Ruvik locked me up in this cell. Get the key on the table and unlock this cell.
	I'll tell you what happened when I am out of
	this cell.

```
- Joseph is asking for help.  

3. The image does not open normaly.  
- binwalk Table.jpg
- we see it has some files embedded in it .
- binwalk -e Table.jpg
- we get this 3 files
1) 0.zip
2) Joseph_Oda.jpg
3) key.wav

- Listening to key.wav its a voice or something .
- Doing some research its a morse code.
- using online decoder am able to decode it. = “showme”

- For the image its joseph i quees ,used exiftool but got nothing then tried steghide using the passphrase “SHOWME”
- It worked and got “thankyou.txt"
- concatenate to get
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/8.png)
**THE FTP DETAILS AND I THINK THAT'S IT FOR WEB.**
# ftp

ftp details
	user = `joseph`
	password = `intotheterror445`
ls we get two files one is binary that accepts commands  
wrote a python script that exploits it  
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/9.png)

running the script we get a text 
![](/assets/img/try%20hack%20me%20/Easy/Psycho_Break/10.png)

decode it to get  `KIDMANSPASSWORDISSOSTRANGE`
FROM THE FTP WE HAVE GOTTEN THIS CREDENTIALS
```
	kidman
	KIDMANSPASSWORDISSOSTRANGE
```
# ssh
```sh
ssh kidman@10.10.129.236
#username = kidman
#password = KIDMANSPASSWORDISSOSTRANGE
```
we get a shell  
concatenate the user flag = “...”  
Now privesc to root user  

cat /ec/crontab
1. Look at the last job it’s executing a python script (.the_eye_of_ruvik.py) every 2 minutes with ROOT privileges.
2. The python script is open to others or permission configured very badly.
3. What we can do is write (w) whatever we want in the python script & it’ll get executed with ROOT privileges.

created a python3 reverse shell in that python script file & just wait for 2 minutes to get the reverse shell connection to my system.  
```sh
cat /root/root.txt 
# “BA33BDF5B8A3B......”
```