---
title: TryHackMe - OverlayFS
author: Bonface
date: 2024-10-31 00:00:00 +0000
categories: [TryHackMe, Easy]
tags: [tryhackme, linux, nmap, privesc, ssh, gcc]
---

# Intro

OverlayFS is a Linux kernel module that allows the system to combine several mount points into one, so that you can access all the files from each within one directory structure.  

## About the vuln

## Task
ssh to the machine
ip=`10.10.215.83`

## Task
SSH into the machine with the credentials provided in the task text.
```sh
ssh overlay@10.10.215.83
```
## Task
Grab the source code for the exploit from SSD-Disclosure here and save it as exploit.c on the target machine.  
Step go to the site and copy the code then use nano text editor to create the file and save it.`  

## Task
Compile the exploit with gcc.  
Step
```sh
gcc -o exploit exploit.c
```

## Task
Run your compiled exploit, and get root!  
What's the flag in `/root/`?  
Step
```sh
cd / #to the home directory
cd root #into the root directory
ls #then 
cat flag.txt 
```