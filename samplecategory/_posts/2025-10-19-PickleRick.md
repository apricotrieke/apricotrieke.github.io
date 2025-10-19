# Pickle Rick

https://tryhackme.com/room/picklerick

A Rick and Morty CTF. Help turn Rick back into a human!

---

---

# Task 1: First ingredient

<aside>
💡

What is the first ingredient that Rick needs?

</aside>

## Reconnaissance:

I’ll start with a classic nmap scan!

### Command Breakdown: nmap

```bash
nmap -A -vv *IP*
```

| nmap | Invoke the nmap command |
| --- | --- |
| -A  | Aggressive/Advanced scan, pools together a multitude of useful flags. Enables OS detection (**-O**), version scanning (**-sV**), script scanning (**-sC**) and traceroute (**--traceroute**) |
| -vv | Very verbose output |
| IP | Fill this field in with the IP of machine to be scanned |

Output:

```bash
genghis@khan:~$ nmap -A -vv 10.10.193.176
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-07 17:52 PDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:52
Completed NSE at 17:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:52
Completed NSE at 17:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:52
Completed NSE at 17:52, 0.00s elapsed
Initiating Ping Scan at 17:52
Scanning 10.10.193.176 [4 ports]
Completed Ping Scan at 17:52, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:52
Completed Parallel DNS resolution of 1 host. at 17:52, 0.01s elapsed
Initiating SYN Stealth Scan at 17:52
Scanning 10.10.193.176 [1000 ports]
Discovered open port 22/tcp on 10.10.193.176
Discovered open port 80/tcp on 10.10.193.176
Completed SYN Stealth Scan at 17:52, 3.74s elapsed (1000 total ports)
Initiating Service scan at 17:52
Scanning 2 services on 10.10.193.176
Completed Service scan at 17:52, 6.48s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.193.176
Initiating Traceroute at 17:52
Completed Traceroute at 17:52, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 17:52
Completed Parallel DNS resolution of 2 hosts. at 17:52, 0.01s elapsed
NSE: Script scanning 10.10.193.176.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:52
NSE Timing: About 99.30% done; ETC: 17:52 (0:00:00 remaining)
NSE Timing: About 99.65% done; ETC: 17:53 (0:00:00 remaining)
NSE Timing: About 99.65% done; ETC: 17:53 (0:00:00 remaining)
NSE Timing: About 99.65% done; ETC: 17:54 (0:00:00 remaining)
Completed NSE at 17:54, 122.30s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:54
Completed NSE at 17:54, 1.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
Nmap scan report for 10.10.193.176
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2025-05-07 17:52:08 PDT for 140s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 fa:c5:fb:88:3d:4d:6a:fa:2f:d7:24:d2:4f:37:3e:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKTR0+jAI0FuDfPruVH1NAux/oSi1hNAZS1BJZCfrNtj
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=5/7%OT=22%CT=1%CU=36971%PV=Y%DS=4%DC=T%G=Y%TM=681C00C4
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11
OS:NW7%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 13.472 days (since Thu Apr 24 06:35:02 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   8.90 ms   10.2.0.1
2   ... 3
4   139.04 ms 10.10.193.176

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.63 seconds
           Raw packets sent: 1213 (54.098KB) | Rcvd: 1041 (42.366KB)
```

Okay, so we see ssh and a webserver. I’ll start by enumerating the webserver with a bruteforce attack to search for directories with gobuster.

### Command Breakdown: gobuster

```bash
gobuster dir -u http://10.10.0.161 -w /usr/share/wordlists/dirb/common.txt -t 40 -x php,txt,html -o gobuster.txt
```

| gobuster | Invoke the gobuster command. https://github.com/OJ/gobuster |
| --- | --- |
| dir | The mode, meaning you're brute-forcing directories and files on a web server. |
| -u [http://10.10.0.161](http://10.10.0.161/) | The target URL to scan. In this case, it’s a web server running on IP 10.10.0.161 |
| -w /usr/share/wordlists/dirb/common.txt | The wordlist file used to guess directory and file names. This one is a common list included in many pentesting distros (like Kali). |
| -t 40 | Sets the number of concurrent threads to 40. This speeds up the scan but uses more resources. |
| -x php,txt,html | Adds file extensions to search for. Gobuster will append .php, .txt, and .html to the words in the wordlist (e.g., trying login.php, readme.txt, etc.). |
| -o gobuster.txt | Output file. Results will be saved to gobuster.txt. |

For context, I added the option to search for file extensions after failing to find anything from a initial bruteforce attack without the inclusion of those file extensions which yielded nothing :(

```bash
┌──(pollo㉿kali)-[~/tryhackme]
└─$ gobuster dir -u http://10.10.0.161 -w /usr/share/wordlists/dirb/common.txt -t 40 -x php,txt,html -o gobuster.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.161
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.hta.html            (Status: 403) [Size: 276]
/.hta.txt             (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htpasswd.html       (Status: 403) [Size: 276]
/.htaccess.html       (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/.hta.php             (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.10.0.161/assets/]
/denied.php           (Status: 302) [Size: 0] [--> /login.php]
/index.html           (Status: 200) [Size: 1062]
/index.html           (Status: 200) [Size: 1062]
/login.php            (Status: 200) [Size: 882]
/portal.php           (Status: 302) [Size: 0] [--> /login.php]
/robots.txt           (Status: 200) [Size: 17]
/robots.txt           (Status: 200) [Size: 17]
/server-status        (Status: 403) [Size: 276]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                                                          
┌──(pollo㉿kali)-[~/tryhackme]
```

Keen observers will realize this scan was done on another machine (I was having network issues, and I have slow hardware.)

Here we have a couple of interesting finds, we have a login page as a possible attack vector. At this point I decided to curl the homepage for more potential finds.

```html
genghis@khan:~/Boxes/PickleRick$ curl 10.10.193.176
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>
```

Sweet, we seem to have some sort of username “R1ckRul3s” maybe this is for the login page we found? At this point I just decided to try the login with this username and try the password “Wubbalubbadubdub” which is the only string of text I found on the robots.txt page. To my surprise I’m greeted with this!

![Screenshot_2025-05-07_18_59_51.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-07_18_59_51.png)

Interesting… Let’s try entering some commands, `ls -l` yields this output 

![Screenshot_2025-05-07_19_02_59.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-07_19_02_59.png)

Okay here’s a lot of stuff, I can use the `less` command to reveal the first ingredient “mr. meeseek hair”

# Task 2: Second Ingredient

<aside>
💡

What is the second ingredient in Rick’s potion?

</aside>

Okay, so we have the ability to input commands and receive outputs from the webserver through this command panel, however we still don’t have permissions to access everything on this page, and we have limited command permissions on the user connected to the command panel. Not only that, but the command panel interface within itself limits our capabilities of navigating the filesystem when compared to something like a shell. It would be nice to get a reverse shell at some point.

## More Recon:

The clue.txt file says

```
Look around the file system for the other ingredient.
```

Okay let’s get some facts straight, I’m gonna try to figure out what user this command panel is actually associated with by using the `whoami` command. Which yields the output

`www-data`

Now I want to gain more information about what other users there are on the system, so I try to use `less` to output the /etc/passwd file. This is a file that can be found on Linux systems that contains user account information. See here for more details (https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
landscape:x:103:105::/var/lib/landscape:/usr/sbin/nologin
tss:x:112:119:TPM software stack,,,:/var/lib/tpm:/bin/false
tcpdump:x:113:120::/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:114:121:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

Okay there’s a lot of users, and a couple of them look maybe interesting? At this point I also wanted to see if I could use the find command to see if I could find a file on the system with a name that contains the word ingredient

### Command Breakdown: find

```bash
find / -name **ingredient*
```

| find | Invoke the find command |
| --- | --- |
| / | Indicates that we are starting out search from the root directory |
| -name | Specifies the next argument is a string of text we are looking for in the name of a file |
| *ingredient  | Argument to -name flag, looking for the string ingredient in the name of file. The * characters make it so it’s looking for that string independent of ordering within the name of file. |

This find yields the output 

`/home/rick/second ingredients`

Okay so we know where the file is, but I don’t have the permissions to see the contents or traverse to it’s destination through the command panel…

At this point I decided to check if the system had any vulnerable programs on it that I can use to escalate my privileges to any degree, or get a reverse shell. 

I checked to see if it was running python with the command

```bash
python3 --version
```

which gave me the output

`Python 3.8.10`

Okay, we are running an old version of python. At this point, I decided to try to leverage this outdated python version to get a reverse shell. 

## Reverse Shell:

For generating my payload, I used the following website:

https://www.revshells.com/

This website is very convenient because it generates a multitude of different reverse shell payloads, and automatically fills in your IP and port information, and also gives you a command to copy for your listener

![Screenshot_2025-05-08_09_08_14.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-08_09_08_14.png)

Once we’ve cooked up our payload, our next step towards getting the reverse shell is spinning up our listener. Even though this website generates our listener for us, let’s do a command breakdown on the listener command!

### Command Breakdown: nc

```bash
nc -lvnp 4444
```

| nc | Invokes the netcat command |
| --- | --- |
| -l | Used to specify that **nc** should listen for an incoming connection rather than initiate a connection to a remote host. |
| -v | Give more verbose output. |
| -n | Do not do any DNS or service lookups on any specified addresses, hostnames or ports. |
| -p 4444 | Specify source port to listen from |

So, let’s go ahead and punch it into the command line!

![Screenshot_2025-05-08_09_53_59.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-08_09_53_59.png)

Alright, the listener seems to be working. Now let’s input our payload to the command panel…

![Screenshot_2025-05-08_09_59_17.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-08_09_59_17.png)

After clicking execute, let’s check back on our terminal window that we ran the listener on

![Screenshot_2025-05-08_10_00_05.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-08_10_00_05.png)

Sweet! We’ve got a shell.

Now let’s navigate to where we found that second ingredient at `/home/rick/second ingredients` and see if we can read it.

![Screenshot_2025-05-08_10_04_17.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/Screenshot_2025-05-08_10_04_17.png)

Nice! That’s one more ingredient down.

# Task 3: Last Ingredient

I’m gonna be perfectly honest, I spent a long time here overthinking what I needed to do, looking all over the place and thinking for a long time. Then at one point I realized I never checked to see if I have super user privileges as www-data, and then I just decided to try using a command with `sudo` and it worked! At that point I used `sudo -l` to see how many commands I had super user privileges for.

![1.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/1.png)

Oh? All of them? Without needing a password? That’s nice.

A simple `sudo su -`  switches me to the root user, and I’m greeted with this

 

![2.png](Pickle%20Rick%201ed559b52dc8804e9aacf7167c45b28f/2.png)

At this point I couldn’t tell whether or not to be happy I had finally figure it out, or disappointed in myself that the final step that had taken me the longest time, was in fact, the simplest. 

# Conclusion:

This was a really fun CTF! It reinforced a lot of the topics I’ve seen while doing a lot of other boxes, and was it’s own fun unique little adventure. I think the biggest takeaway for me here was that Occam was really onto something with that razor. I really need to check the most obvious things first and make sure I’ve exhausted all of the simplest options before I start overthinking things.