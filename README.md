AandEPHP
==========


![alt aandePHP](http://nwabytes.com/AandEPHP.png)

Apache-Nginx(proxy) Mysql PHP Installer for Debian 8

Low memory usage

First I'd like to say this script installs extra software some people might find useless.

Some of the extra software installed
(dnsutils tmux nano wget curl grc xtail htop iftop vim-nox grc xtail)

Installs and configures ufw
open: 80,sshport,443
out going open

Sets up fail2ban
Downloads adminer with random filename


Secures sysctl.conf

Change ssh port

Option for ssh keys only ssh login


Sets limits and secure php
Nginx from ngix repo
Letsencrypt


Setup logwatch with offsite email

Mysql default storage myisam

Tested on Debian 8

Installs Apache2.4 Nginx (as proxy), Mariadb and PHP5 from debian repos.
Option for installing webmin from repos.
Setting up user and virutal host in /home/user/domain.com
Random mysql root password in /root/.my.cnf and mysql user for the added domain.
PHP few setting for security and performance.


Install: No install. just run the script



**Run bash lighttphpa.sh as root**

### Quick Install

     # Install git and clone AandEPHP
    wget https://github.com/slowz/aandephp/archive/v1.0.tar.gz
    tar zxf v1.0.tar.gz
    cd aandephp

**You must set the options in options.conf**

`bash aandephp.sh install`

`bash aandephp.sh adddomain` ## adds /home/user/domain/public_html and adds info to lighttpd

`bash aandephp.sh version` ## Show version
