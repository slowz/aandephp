#!/usr/bin/env bash
##########################################
# Some code copied from lownendbox script.
# Tested with Debian 8 32/64bit.
# Script author <kevin@nwabytes.com>
# Website https://github.com/slowz/aandephp
# GPLV3
##########################################
# Colors
VER="1.0.1"
>install.log
>install-error.log
#echo -e "\t\t***** INSTALLED $(date +%B) $(date +%Y) *****"
exec >  >(tee -a install.log)
exec 2> >(tee -a install-error.log >&2)
source ./options.conf
EPASS=$(perl -e 'print crypt("$UPASSWD", "salt"),"\n"')
ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
#COL_GREEN=$ESC_SEQ"32;01m"
#COL_YELLOW=$ESC_SEQ"33;01m"
COL_BLUE=$ESC_SEQ"34;01m"
#COL_MAGENTA=$ESC_SEQ"35;01m"
#COL_CYAN=$ESC_SEQ"36;01m"
## Path to php.ini
SSHD_CONF="/etc/ssh/sshd_config"
#PHP_INI_DIR="/etc/php5/apache2/php.ini"
#PHP_FPM_INI_DIR="/etc/php5/fpm/php.ini"
# Gen random string
RANSTR=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w5 | head -n1)
#RANSTR=$RANDOM
SERVERIP=$(ip route get 8.8.8.8 | awk 'NR==1 {print $NF}')
function aeinstall ()
{
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get -y \
        -o DPkg::Options::=--force-confdef \
        -o DPkg::Options::=--force-confold \
        install "$@"
}
function check_sanity {
    # Do some sanity checking.
    if [ "$(/usr/bin/id -u)" != "0" ]
    then
        die 'Must be run by root user!'
    fi
    if [ "$HASEDIT" = "no" ]; 
    then
        die "Please edit the options file!"
    fi
    ## Allow Debian 8
    #if ! grep -q "Debian GNU/Linux 7" /etc/issue
    #then
    #die "Distribution is not supported. Debian Wheezy only"
    #fi
}
function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}
function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=$(cat "$SALT"; echo "$1" | md5sum | base64)
    echo "${password:0:13}"
}
function print_info {
    echo -n -e '\e[1;36m'
    echo -n "$1"
    echo -e '\e[0m'
}
function print_warn {
    echo -n -e '\e[1;33m'
    echo -n "$1"
    echo -e '\e[0m'
}
function install_site {
    mkdir /home/"$USERID"/logs
    mkdir -p /home/"$USERID"/"$DOMAIN"/public_html
    chown www-data:www-data /home/"$USERID"/logs
cat > "/home/$USERID/$DOMAIN/public_html/index.php" <<END
"$DOMAIN" <br>
It Works!
END
    echo "<?php phpinfo(); ?>" > /home/"$USERID"/"$DOMAIN"/public_html/phpinfo_"$RANSTR".php
    cp ./config/vhost.conf  /etc/apache2/sites-enabled/"$DOMAIN".conf
    sed -i "s/DOMAIN/$DOMAIN/g" /etc/apache2/sites-enabled/"$DOMAIN".conf
    sed -i "s/USERID/$USERID/g" /etc/apache2/sites-enabled/"$DOMAIN".conf
    cp ./config/nginx_vhost.conf  /etc/nginx/conf.d/"$DOMAIN".conf
    sed -i "s/DOMAIN/$DOMAIN/g" /etc/nginx/conf.d/"$DOMAIN".conf
    sed -i "s/USERID/$USERID/g" /etc/nginx/conf.d/"$DOMAIN".conf
    chown -R www-data:www-data /home/"$USERID"/"$DOMAIN"
    service apache2 restart
    service nginx restart
}
function install_logwatch {
aeinstall logwatch libdate-manip-perl libsys-cpuload-perl libsys-cpu-perl
    sed -i "s/Output = stdout/Output = mail/" /usr/share/logwatch/default.conf/logwatch.conf
    sed -i "s/MailTo = root/MailTo = $ROOTEMAIL/" /usr/share/logwatch/default.conf/logwatch.conf
    sed -i "s/Detail = Low/Detail = High/" /usr/share/logwatch/default.conf/logwatch.conf
    sed -i "s/MailFrom = Logwatch/MailFrom = Logwatch@$HNAME/" /usr/share/logwatch/default.conf/logwatch.conf
    # Allow mail delivery from localhost only
    /usr/sbin/postconf -e "inet_interfaces = loopback-only"
}
function secure_mysql {
    SECURE_MYSQL=$(expect -c "
        set timeout 10
        spawn mysql_secure_installation
        expect \"Enter current password for root (enter for none):\"
        send \"$passwd\r\"
        expect \"Change the root password?\"
        send \"n\r\"
        expect \"Remove anonymous users?\"
        send \"y\r\"
        expect \"Disallow root login remotely?\"
        send \"y\r\"
        expect \"Remove test database and access to it?\"
        send \"y\r\"
        expect \"Reload privilege tables now?\"
        send \"y\r\"
        expect eof
        ")

    echo "$SECURE_MYSQL"
}
function secure_server {
    echo "Default page." > /var/www/html/index.html
    echo "Default page." > /usr/share/nginx/html/index.html
    cat ./tpl/motd > /etc/motd
    cat ./tpl/motd > /etc/issue
    cat ./tpl/motd > /etc/issue.net
    sed -i s/server.com/"$HNAME"/g /etc/motd /etc/issue /etc/issue.net
    ##sysctl
    sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.icmp_echo_ignore_broadcasts = 1/net.ipv4.icmp_echo_ignore_broadcasts = 1/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.icmp_ignore_bogus_error_responses = 1/net.ipv4.icmp_ignore_bogus_error_responses = 1/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
    sed -i "s/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/g" /etc/sysctl.conf
echo "#
# Controls the use of TCP syncookies
net.ipv4.tcp_synack_retries = 2
# Increasing free memory
vm.min_free_kbytes = 16384
" >> /etc/sysctl.conf
    sysctl -p
    sed -i "s/^Port [0-9]*/Port $SSHP/" ${SSHD_CONF}
    sed -i "s/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0:$SSHP/" ${SSHD_CONF}
    service ssh restart
    ## Set cron for security updates and email if needed.
    aeinstall unattended-upgrades apt-listchanges

    if [ "$SSHKEYONLY" = "yes" ]; then
        sed -i "s/.*RSAAuthentication.*/RSAAuthentication yes/g" ${SSHD_CONF} 		
        sed -i "s/.*PubkeyAuthentication.*/PubkeyAuthentication yes/g" ${SSHD_CONF} 		
        sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/g" ${SSHD_CONF}
        sed -i "s/.*X11Forwarding yes/X11Forwarding no/g" ${SSHD_CONF}
        printf "\nUseDNS no" >> ${SSHD_CONF}
        service ssh restart
    else
        echo -e "${COL_BLUE} ssh password login active." 
        echo -e "${COL_RESET}"
    fi
    if [ "$IFIREWALL" = "yes" ]; then
        aeinstall ufw
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow "$SSHP"
        ufw allow http
        ufw allow https
        if [ "$INSTWEBMIN" = "yes" ]; then
            ufw allow "$WEBMP"
        else
            echo -e "${COL_BLUE} Webmin not installed."
            echo -e "${COL_RESET}"
        fi
        ufw limit ssh
        yes | ufw enable
        ufw status
    else
        echo -e "${COL_BLUE}ufw not installed."
        echo -e "${COL_RESET}"
    fi
    sed -i "s/ServerTokens.*/ServerTokens Prod/g" /etc/apache2/conf-enabled/security.conf
    sed -i "s/ServerSignature.*/ServerSignature Off/g" /etc/apache2/conf-enabled/security.conf
    sed -i "s/Timeout 300/Timeout 30/g" /etc/apache2/apache2.conf

    #Install suhosin
    echo 'deb http://repo.suhosin.org/ debian-jessie main' >> /etc/apt/sources.list
    wget https://sektioneins.de/files/repository.asc
    apt-key add repository.asc
    aeinstall php5-suhosin-extension
    echo "suhosin.executor.func.blacklist = assert,unserialize,exec,popen,proc_open,passthru,shell_exec,system,hail,parse_str,mt_srand" >> /etc/php5/mods-available/suhosin.ini 
    php5enmod suhosin
    aeinstall apt-transport-https
    aeinstall libpam-pwquality
    echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > /etc/apt/apt.conf.d/20auto-upgrades
    sed -i "s/user@domain.tld/$ROOTEMAIL/g" /etc/rkhunter.conf
    sed -i "s/me@mydomain/$ROOTEMAIL/g" /etc/rkhunter.conf
    sed -i "s/root@mydomain//g" /etc/rkhunter.conf
    sed -i "s/#MAIL-ON-WARNING/MAIL-ON-WARNING/g" /etc/rkhunter.conf
    sed -i "s/#MAIL_CMD/MAIL_CMD/g" /etc/rkhunter.conf
}
function create_database {
    USERID="${USERID:0:15}"
    passwd=$(get_password "$USERID@mysql")
    dbname="${USERID}_$RANDOM"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$USERID\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql
cat > "/home/$USERID/.my.cnf" <<END
[mysql]
user = "$USERID"
password = $passwd
database = $dbname
END
    chown "$USERID":"$USERID" /home/"$USERID"/.my.cnf
}
function tune_php {
    if [ -f /etc/php5/apache2/php.ini ]
    then
        # Tweak fpm php.ini
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^max_execution_time.*/max_execution_time = ${PHP_MAX_EXECUTION_TIME}/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^memory_limit.*/memory_limit = ${PHP_MEMORY_LIMIT}/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^max_input_time.*/max_input_time = ${PHP_MAX_INPUT_TIME}/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^post_max_size.*/post_max_size = ${PHP_POST_MAX_SIZE}/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^upload_max_filesize.*/upload_max_filesize = ${PHP_UPLOAD_MAX_FILESIZE}/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^expose_php.*/expose_php = Off/" {} \;
find /etc/php5/ -type f -name 'php.ini' -exec sed -i "s/^disable_functions.*/disable_functions = exec,system,passthru,shell_exec,escapeshellarg,escapeshellcmd,proc_close,proc_open,dl,popen,show_source/" {} \;
cat > /etc/php5/mods-available/apcu.ini <<END
extension=apcu.so
apc.enabled=1
apc.shm_segments=1
apc.shm_size=32M
apc.ttl=7200
apc.user_ttl=7200
apc.num_files_hint=1024
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.max_file_size = 1M
apc.post_max_size = 1000M
apc.upload_max_filesize = 1000M
apc.enable_cli=0
apc.rfc1867=0
END
    fi
}
function install_mysql {
    # Install the Mariadb packages
    aeinstall mariadb-server
    aeinstall mariadb-client
    passwd=$(get_password root@mysql)
    mysqladmin password "$passwd"
cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
    chmod 600 ~/.my.cnf
    #echo -e "\e[31;01m `cat ~/.my.cnf`"
    #echo -e "${COL_RESET}"
}
function update_timezone {
    echo "$TIMEZ" > /etc/timezone
    dpkg-reconfigure -f noninteractive tzdata
}
function install_webmin {
    if [ "$INSTWEBMIN" = "yes" ]; then
        echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/sources.list
        wget -q http://www.webmin.com/jcameron-key.asc -O- | apt-key add -
        aeinstall webmin
        sed -i "s/=10000/=$WEBMP/g" /etc/webmin/miniserv.conf
        service webmin restart
    fi
}
function install_prefered {
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string $HNAME" | debconf-set-selections
    echo "postfix postfix/destinations string localhost.localdomain, localhost" | debconf-set-selections
	aeinstall expect postfix libapache2-mod-php5 libapache2-mod-rpaf lsb-release man wget dialog curl apache2 php5 php5-cgi php5-gd php5-apcu php5-curl php5-gd php5-intl php5-mcrypt php5-imap php-gettext php5-mysql php5-sqlite php5-cli php-pear sqlite3 php5-imagick fail2ban python-gamin bsd-mailx libapache2-modsecurity geoip-database-contrib bsdutils dnsutils tmux nano wget htop iftop vim-nox grc xtail mc iotop zip unzip sqlite3 ca-certificates ncdu rkhunter goaccess
    php5enmod pdo
    php5enmod mcrypt
    php5enmod imap
    # Disable opcache causing 500 errors
    php5dismod opcache
	aeinstall nginx nginx-module-geoip
    rm -rf /etc/nginx/nginx.conf 
    cp ./config/nginx.conf  /etc/nginx/nginx.conf
    a2enmod rewrite
    a2enmod security2
    sed -i "s/80/8080/g" /etc/apache2/ports.conf
    sed -i "s/443/1443/g" /etc/apache2/ports.conf
    sed -i "s/80/8080/g" /etc/apache2/sites-enabled/*
    sed -i "s/443/1443/g" /etc/apache2/sites-enabled/*
    sed -i "s/^*RPAFproxy_ips 127.0.0.1 ::1/RPAFproxy_ips 127.0.0.1 ::1 $SERVERIP/g" /etc/apache2/mods-available/rpaf.conf
}
function restartall {
    service apache2 restart
    service nginx restart
    service postfix restart
    service mysql restart
    service fail2ban restart
}
function adddomain {
    echo -e "${COL_BLUE} Enter Domain name:"
    echo -e "${COL_RESET}"
    read -r DOMAIN2
    mkdir -p /home/"$USERID"/"$DOMAIN2"/public_html
cat > "/home/$USERID/$DOMAIN2/public_html/index.php" <<END
"$DOMAIN2" <br>
It Works!
END
    chown -R www-data:www-data /home/"$USERID"/"$DOMAIN2"
    cp ./config/vhost.conf  /etc/apache2/sites-enabled/"$DOMAIN2".conf
    sed -i "s/DOMAIN/$DOMAIN2/g" /etc/apache2/sites-enabled/"$DOMAIN2".conf
    sed -i "s/USERID/$USERID/g" /etc/apache2/sites-enabled/"$DOMAIN2".conf
    cp ./config/nginx_vhost.conf  /etc/nginx/conf.d/"$DOMAIN2".conf
    sed -i "s/DOMAIN/$DOMAIN2/g" /etc/nginx/conf.d/"$DOMAIN2".conf
    sed -i "s/USERID/$USERID/g" /etc/nginx/conf.d/"$DOMAIN2".conf
    chown -R www-data:www-data /home/"$USERID"/"$DOMAIN2"
    service apache2 restart
    service nginx restart
}
function deldomain {
    echo -e "${COL_BLUE} Enter Domain name:"
    echo -e "${COL_RESET}"
    read -r DELDOMAIN
    rm -rf /etc/apache2/sites-enabled/"$DELDOMAIN".conf
    rm -rf /etc/nginx/conf.d/"$DELDOMAIN".conf
    rm -rf /home/"$USERID"/"${DELDOMAIN:?}"/
    service apache2 restart
    service nginx restart
    echo "Domain $DELDOMAIN was deleted. But we've saved the log files for the domain'"
}
function install_letsei {
    aeinstall letsencrypt python-certbot-nginx -t jessie-backports
    #/usr/bin/certbot --nginx --email "$ROOTEMAIL" -d "$DOMAIN" -d www."$DOMAIN" --agree-tos
}
function install {
    echo "$HNAME" > /etc/hostname
    cp /etc/hosts /etc/hosts.bak
    echo "127.0.0.1    $HNAME" >> /etc/hosts
    sysctl kernel.hostname="$HNAME"
    hostname -F /etc/hostname
    if [ "$ADDSWAP" = "yes" ]; then
        fallocate -l 1048M /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo "/swapfile none swap defaults 0 0" >> /etc/fstab
        echo "#
vm.swappiness=10
vm.vfs_cache_pressure = 50
" >> /etc/sysctl.conf
    fi
echo "
deb http://http.us.debian.org/debian/ jessie main contrib non-free
deb-src http://http.us.debian.org/debian/ jessie main contrib non-free

deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free

#jessie-updates, previously known as 'volatile'
deb http://http.us.debian.org/debian/ jessie-updates main contrib non-free
deb-src http://http.us.debian.org/debian/ jessie-updates main contrib non-free
deb http://ftp.debian.org/debian jessie-backports main contrib non-free
deb http://nginx.org/packages/debian/ jessie nginx
" > /etc/apt/sources.list
    wget http://nginx.org/keys/nginx_signing.key  -O- | apt-key add -
    cp ./tpl/bashrc-root /root/.bashrc
	aeinstall debconf-utils libc-bin sudo locales
    sed -i "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen
    /usr/sbin/locale-gen
    apt-get purge apache2* samba* bind9* mysql-* lighttpd* nginx* exim4* -y
    apt-get dist-upgrade -y
    addgroup "$USERID"
    sleep 1
    useradd -m -p "$EPASS" "$USERID" -g "$USERID" -s /bin/bash
    cp ./tpl/bashrc-user /home/"$USERID"/.bashrc
    chown "$USERID":"$USERID" /home/"$USERID"/.bashrc
    sleep 1
    install_prefered
    install_letsei
    echo "Please wait. Generating 4096 dhparam.pem"
    mkdir /etc/nginx/ssl
    openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
    install_site
    usermod -a -G www-data "$USERID"
    service apache2 restart
    tune_php
    service apache2 restart
    install_mysql
    sleep 1
    secure_mysql
    create_database
    update_timezone
    secure_server
    ssh-keygen -f ~/.ssh/id_rsa -t rsa -N ''
    sudo -u "$USERID" /usr/bin/ssh-keygen -f /home/"$USERID"/.ssh/id_rsa -t rsa -N ''
    install_webmin
    wget -q https://www.adminer.org/latest-mysql-en.php -O /home/"$USERID"/"$DOMAIN"/public_html/adminer_"$RANSTR".php
    chown www-data:www-data /home/"$USERID"/"$DOMAIN"/public_html/adminer_"$RANSTR".php
}
function start_aandephp {
    if [ -f /root/.aandephp ] ;
    then
        echo -e "${COL_RED}You've already run bash install.sh install ${COL_RESET}"
        exit
    fi
    touch /root/.aandephp
    install
    install_logwatch
    restartall
    echo -e "${COL_BLUE}Adminer installed at http://$DOMAIN/adminer_$RANSTR.php"
    echo -e "PHPinfo at http://$DOMAIN/phpinfo_$RANSTR.php"
    if [ "$INSTWEBMIN" = "yes" ]; then
        echo -e "Webmin https://$SERVERIP:$WEBMP"
    else
        echo -e "Webmin not installed"
    fi
    echo -e "Domain MySql "
    cat /home/"$USERID"/.my.cnf
    echo -e "${COL_RESET}"
}
function lversion {
    echo $VER
}
##############################################################################################################
check_sanity
case "$1" in
    -i| --version) start_aandephp;;
	-ad| --addomain) adddomain;;
	-v| --version) lversion;;
	-dd| --deldomain) deldomain;;
	*) echo -e "${COL_RED} Sorry, wrong option!"
echo -e ""
for option in -i -ad -v -dd
do
    echo -e "${COL_BLUE} bash aandephp.sh $option"
    echo -e "${COL_RESET}"
done
;;
esac
export PATH=/bin:/usr/bin:/sbin:/usr/sbin
