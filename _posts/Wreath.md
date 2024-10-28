Wreath is designed as a learning resource for beginners with a primary focus on:
- Pivoting
- Working with the Empire C2 (**C**ommand and **C**ontrol) framework
- Simple Anti-Virus evasion techniques


The following topics will also be covered, albeit more briefly:
- Code Analysis (Python and PHP)
- Locating and modifying public exploits  
- Simple web-app enumeration and exploitation  
- Git Repository Analysis
- Simple Windows Post-Exploitation techniques
- CLI Firewall Administration (CentOS and Windows)
- Cross-Compilation techniques
- Coding wrapper programs
- Simple exfiltration techniques  
- Formatting a pentest report


The room focuses more on teaching the skills rather than the actual enumeration.
The room also has a zipfile containing the tools demonstrated throughout the tasks.

First you have to connect to the network.
- Download the network openvpn file from the access page
- use the openvpn commad to connect


## Backstory

An old friend (Thomas) from the university call from the blue.You get to catch up then he tells you that he has a job for you since he heard that you were into hacking and he has the lab setup that you can play/test it .
**Do you agree ??** 

## Brief

we get a brief layout of the machines in the network.

`*_There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference._*`

From this we can take away the following pieces of information:

- There are three machines on the network
- There is at least one public facing webserver
- There is a self-hosted git server somewhere on the network
- The git server is internal, so Thomas may have pushed sensitive information into it  
- There is a PC running on the network that has antivirus installed, meaning we can hazard a guess that this is likely to be Windows
- By the sounds of it this is likely to be the server variant of Windows, which might work in our favour.
- The (assumed) Windows PC cannot be accessed directly from the webserver


#check_that_site

## Enumeration

`Enumeration` is a data gathering process wherein a cyber attacker extracts information about a network, such as host IP addresses, DNS and user names, or sharing and network protocols, intending to find weak points and breach the network.

