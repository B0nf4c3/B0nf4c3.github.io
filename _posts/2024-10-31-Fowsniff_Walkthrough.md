---
title: TryHackMe - Fowsniff_Walkthrough
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe, Easy]
tags: [tryhackme, linux, nmap, privesc, http, ssh, crack]
---

** My ip address **
`10.10.28.128`

# nmap scan
```sh
	sudo nmap -v -sS -sC 10.10.28.128 | tee nmap.txt
```


```sh
	Discovered open port 80/tcp on 10.10.28.128
	Discovered open port 143/tcp on 10.10.28.128
	Discovered open port 110/tcp on 10.10.28.128
	Discovered open port 22/tcp on 10.10.28.128
```


- From the hint we get a url 
	`https://github.com/berzerk0/Fowsniff`

- The file contains usernames and the hashes
- for `seina's` hashed password `90dc16d47114aa13671c697fd506cf26`
- I used crack station and got the password as `scoobydoo2`

# ssh 
```sh
	ssh seina@10.10.28.128
```	