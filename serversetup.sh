#!/bin/sh

function die
{
	echo "$1" 1>&2
	exit 1
}

clear

if [ -z "${mysql_root_password}" ]; then
  read -p "MySQL root password:" mysql_root_password
  mysql_root_password=${mysql_root_password}
fi

admin_password=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)

clear

if [ -z "${server_type}" ]; then
  read -p "Choose server type
1. webserver [x]
2. mailserver
--
" server_type
  server_type=${server_type:-1}
fi

clear

echo "Setting timezone"
cp /usr/share/zoneinfo/Europe/London /etc/localtime

if [ $server_type == "1" ]; then
	echo "Configuring webserver"
	echo "Installing dependencies.."
	yum install -y httpd php php-mbstring postfix mysql mysql-server php-mysql php-gd php-zip mod_ssl vsftpd pam_mysql nano wget mlocate mod_evasive mailx

	echo "Configure services"
	systemctl enable httpd.service
    systemctl enable firewalld.service
    systemctl enable postfix.service
    systemctl enable mariadb.service
    systemctl enable vsftpd.service

    echo "Configure Apache"
    cat <<EOF > /etc/httpd/conf.d/vhost.conf
#IncludeOptional /var/www/vhosts/*/conf/vhost.con[f]

# get the server name from the Host: header
UseCanonicalName Off

# this log format can be split per-virtual-host based on the first field
LogFormat "%V %h %l %u %t \"%r\" %s %b" vcommon
CustomLog logs/access_log vcommon

# include the server name in the filenames used to satisfy requests
VirtualDocumentRoot /var/www/vhosts/%0/httpdocs
EOF

    echo "Configure PHP"
    sed -i 's/short_open_tag = Off/short_open_tag = On/g' /etc/php.ini
    grep "short_open_tag =" /etc/php.ini

    sed -i 's/error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\/error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_NOTICE & ~E_WARNING/g' /etc/php.ini
    grep "error_reporting =" /etc/php.ini

    sed -i 's/;date.timezone =/date.timezone = "Europe\/London"/g' /etc/php.ini
    grep "date.timezone =" /etc/php.ini

    sed -i 's/auto_prepend_file =/auto_prepend_file= \/var\/www\/vhosts\/prepend.php/g' /etc/php.ini
    grep "auto_prepend_file" /etc/php.ini

    if [ ! -d /var/www/vhosts/ ]; then
    mkdir /var/www/vhosts/
    fi

    chown apache /var/www/vhosts/
    chmod 755 /var/www/vhosts/

    cat <<EOF > /var/www/vhosts/prepend.php
<?php
if( $_SERVER["DOCUMENT_ROOT"] === '/var/www/html' ){
    $_SERVER["DOCUMENT_ROOT"] = '/var/www/vhosts/'.$_SERVER['HTTP_HOST'];

    if( is_link($_SERVER["DOCUMENT_ROOT"]) ){
        $_SERVER["DOCUMENT_ROOT"] = '/var/www/vhosts/'.readlink($_SERVER["DOCUMENT_ROOT"]);
    }

    $_SERVER["DOCUMENT_ROOT"] .= '/httpdocs';
}

if( $_SERVER['DOCUMENT_ROOT'] ){
    ini_set('open_basedir', $_SERVER['DOCUMENT_ROOT'].':/tmp:/var/www/vhosts/shiftcreate.com/subdomains/lib/httpdocs');
}
?>
EOF

    echo "Configure MySQL"
    systemctl start mariadb.service
    mysqladmin -u root password ${mysql_root_password}

    echo "Configure VSFTPD"
    useradd -G users -s /sbin/nologin -d /home/vsftpd  vsftpd
    if [ ! -f /etc/vsftpd/vsftpd.conf-orig ]; then
        cp -v /etc/vsftpd/vsftpd.conf   /etc/vsftpd/vsftpd.conf-orig
    fi

    cat <<EOF > /etc/vsftpd/vsftpd.conf
# Allow anonymous FTP? (Beware - allowed by default if you comment this out).
anonymous_enable=NO
#
# Uncomment this to allow local users to log in.
# When SELinux is enforcing check for SE bool ftp_home_dir
local_enable=YES
#
# Uncomment this to enable any form of FTP write command.
write_enable=YES
#
# Default umask for local users is 077. You may wish to change this to 022,
# if your users expect that (022 is used by most other ftpd's)
local_umask=022
#
# Uncomment this to allow the anonymous FTP user to upload files. This only
# has an effect if the above global write enable is activated. Also, you will
# obviously need to create a directory writable by the FTP user.
# When SELinux is enforcing check for SE bool allow_ftpd_anon_write, allow_ftpd_full_access
#anon_upload_enable=YES
#
# Uncomment this if you want the anonymous FTP user to be able to create
# new directories.
#anon_mkdir_write_enable=YES
#
# Activate directory messages - messages given to remote users when they
# go into a certain directory.
dirmessage_enable=YES
#
# Activate logging of uploads/downloads.
xferlog_enable=YES
#
# Make sure PORT transfer connections originate from port 20 (ftp-data).
connect_from_port_20=YES
#
# If you want, you can arrange for uploaded anonymous files to be owned by
# a different user. Note! Using "root" for uploaded files is not
# recommended!
#chown_uploads=YES
#chown_username=whoever
#
# You may override where the log file goes if you like. The default is shown
# below.
#xferlog_file=/var/log/xferlog
#
# If you want, you can have your log file in standard ftpd xferlog format.
# Note that the default log file location is /var/log/xferlog in this case.
xferlog_std_format=YES
#
# You may change the default value for timing out an idle session.
#idle_session_timeout=600
#
# You may change the default value for timing out a data connection.
#data_connection_timeout=120
#
# It is recommended that you define on your system a unique user which the
# ftp server can use as a totally isolated and unprivileged user.
#nopriv_user=ftpsecure
#
# Enable this and the server will recognise asynchronous ABOR requests. Not
# recommended for security (the code is non-trivial). Not enabling it,
# however, may confuse older FTP clients.
#async_abor_enable=YES
#
# By default the server will pretend to allow ASCII mode but in fact ignore
# the request. Turn on the below options to have the server actually do ASCII
# mangling on files when in ASCII mode.
# Beware that on some FTP servers, ASCII support allows a denial of service
# attack (DoS) via the command "SIZE /big/file" in ASCII mode. vsftpd
# predicted this attack and has always been safe, reporting the size of the
# raw file.
# ASCII mangling is a horrible feature of the protocol.
#ascii_upload_enable=YES
#ascii_download_enable=YES
#
# You may fully customise the login banner string:
#ftpd_banner=Welcome to blah FTP service.
#
# You may specify a file of disallowed anonymous e-mail addresses. Apparently
# useful for combatting certain DoS attacks.
#deny_email_enable=YES
# (default follows)
#banned_email_file=/etc/vsftpd/banned_emails
#
# You may specify an explicit list of local users to chroot() to their home
# directory. If chroot_local_user is YES, then this list becomes a list of
# users to NOT chroot().
# (Warning! chroot'ing can be very dangerous. If using chroot, make sure that
# the user does not have write access to the top level directory within the
# chroot)
chroot_local_user=YES
#chroot_list_enable=YES
# (default follows)
#chroot_list_file=/etc/vsftpd/chroot_list
#
# You may activate the "-R" option to the builtin ls. This is disabled by
# default to avoid remote users being able to cause excessive I/O on large
# sites. However, some broken FTP clients such as "ncftp" and "mirror" assume
# the presence of the "-R" option, so there is a strong case for enabling it.
#ls_recurse_enable=YES
#
# When "listen" directive is enabled, vsftpd runs in standalone mode and
# listens on IPv4 sockets. This directive cannot be used in conjunction
# with the listen_ipv6 directive.
listen=YES
#
# This directive enables listening on IPv6 sockets. By default, listening
# on the IPv6 "any" address (::) will accept connections from both IPv6
# and IPv4 clients. It is not necessary to listen on *both* IPv4 and IPv6
# sockets. If you want that (perhaps because you want to listen on specific
# addresses) then you must run two copies of vsftpd with two configuration
# files.
# Make sure, that one of the listen options is commented !!
listen_ipv6=NO

# here we use the authentication module for vsftpd to check users name and passw
pam_service_name=vsftpd
userlist_enable=YES
tcp_wrappers=YES

#Adam Jimenez - tutorial edits

# If userlist_deny=YES (default), never allow users in this file
# /etc/vsftpd/user_list , and do not even prompt for a password.
# Note that the default vsftpd pam config also checks /etc/vsftpd/ftpusers
# for users that are denied.
userlist_deny=yes

# here the vsftpd will allow the 'vsftpd' user to login into '/var/www/vhosts/$USER directory
guest_enable=YES
guest_username=vsftpd
local_root=/var/www/vhosts/$USER
user_sub_token=$USER
virtual_use_local_privs=YES
user_config_dir=/etc/vsftpd/vsftpd_user_conf

force_local_data_ssl=NO
force_local_logins_ssl=NO

# PASV - passive ports for FTP (range 44000 - 44100 ; 100 PASV ports,
# REMEMBER to OPEN FIREWALL FOR ALLOWING FTP Passive CONNECTIONS
# check "how to enable Passive FTP in IPTABLES": here or here

pasv_enable=YES
pasv_min_port=44000
pasv_max_port=44100

#fix for 500 OOPS: priv_sock_get_int ?
seccomp_sandbox=NO
EOF

    if [ ! -f /etc/pam.d/vsftpd-orig ]; then
    cp /etc/pam.d/vsftpd /etc/pam.d/vsftpd-orig
    fi

    cat <<EOF > /etc/pam.d/vsftpd
#%PAM-1.0
session     optional     pam_keyinit.so     force revoke
auth required pam_mysql.so user=vsftpd passwd=${admin_password} host=localhost db=vsftpd table=accounts usercolumn=username passwdcolumn=pass crypt=3
account required pam_mysql.so user=vsftpd passwd=${admin_password} host=localhost db=vsftpd table=accounts usercolumn=username passwdcolumn=pass crypt=3
EOF

    mysql -u root -p${mysql_root_password} << EOF
CREATE DATABASE IF NOT EXISTS vsftpd;
CREATE TABLE IF NOT EXISTS vsftpd.accounts (
  id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(50) NOT NULL,
  pass varchar(50) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY username (username)
);
GRANT SELECT ON vsftpd.* TO 'vsftpd'@'localhost' IDENTIFIED BY '${admin_password}';
FLUSH PRIVILEGES;
EOF


    service vsftpd restart

    echo "Configure Firewall"
    service firewalld start
    firewall-cmd --permanent --add-port=21/tcp
    firewall-cmd --permanent --add-service=ftp
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    systemctl start firewalld.service

elif [ $server_type == "2" ]; then
	echo "Configuring mailserver.."
	echo "Installing dependencies.."
	yum install -y postfix dovecot nano dovecot-mysql zip unzip tar php php-mbstring php-mysql httpd mailx mlocate rsync mysql-server php-xml gcc gdbm-devel postgrey vacation

	systemctl enable mariadb.service
    systemctl enable httpd.service

    echo "Configure MySQL"
    systemctl start mariadb.service

    mysql -u root -p${mysql_root_password} << EOF
    CREATE DATABASE IF NOT EXISTS mail;
    USE mail;

CREATE TABLE IF NOT EXISTS domains (
  domain varchar(50) NOT NULL,
  \`usage\` int(11) NOT NULL,
  PRIMARY KEY (domain),
  UNIQUE KEY domain (domain)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS forwardings (
  \`source\` varchar(80) NOT NULL,
  destination text NOT NULL,
  PRIMARY KEY (\`source\`),
  UNIQUE KEY \`source\` (\`source\`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS transport (
  domain varchar(128) NOT NULL DEFAULT '',
  transport varchar(128) NOT NULL DEFAULT '',
  UNIQUE KEY domain (domain)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS users (
  email varchar(80) NOT NULL,
  \`password\` varchar(20) NOT NULL,
  raw varchar(64) NOT NULL,
  \`usage\` int(11) NOT NULL,
  PRIMARY KEY (email),
  UNIQUE KEY email (email)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS vacation (
  email varchar(255) NOT NULL DEFAULT '',
  \`subject\` varchar(255) NOT NULL DEFAULT '',
  body text NOT NULL,
  \`cache\` text NOT NULL,
  domain varchar(255) NOT NULL DEFAULT '',
  created datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  active tinyint(4) NOT NULL DEFAULT '1',
  PRIMARY KEY (email),
  UNIQUE KEY email (email)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS vacation_notification (
  id int(11) NOT NULL AUTO_INCREMENT,
  on_vacation varchar(255) NOT NULL DEFAULT '',
  notified varchar(255) NOT NULL DEFAULT '',
  notified_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;

GRANT SELECT, INSERT, UPDATE, DELETE ON mail.* TO 'mail_admin'@'localhost' IDENTIFIED BY '${admin_password}';
GRANT SELECT, INSERT, UPDATE, DELETE ON mail.* TO 'mail_admin'@'localhost.localdomain' IDENTIFIED BY '${admin_password}';
FLUSH PRIVILEGES;
EOF

    echo "Configure Apache"
    
    if [ ! -d /var/www/vhosts/ ]; then
    mkdir /var/www/vhosts/
    fi
    
    chown apache /var/www/vhosts/
    chmod 755 /var/www/vhosts/

    if [ ! -d /var/www/vhosts/$(hostname) ]; then
    mkdir /var/www/vhosts/$(hostname)
    fi

    cat <<EOF > /etc/httpd/conf.d/mail.conf
NameVirtualHost *:80

<VirtualHost *:80>
DocumentRoot /var/www/html/roundcube
</VirtualHost>

<VirtualHost *:80>
DocumentRoot /var/www/vhosts/$(hostname)
ServerName $(hostname)
</VirtualHost>
EOF

    echo "Configure Postfix"
    cat <<EOF > /etc/postfix/mysql-virtual_domains.cf
user = mail_admin
password = ${admin_password}
dbname = mail
query = SELECT domain AS virtual FROM domains WHERE domain='%s'
hosts = 127.0.0.1
EOF

    cat <<EOF > /etc/postfix/mysql-virtual_forwardings.cf
user = mail_admin
password = ${admin_password}
dbname = mail
query = SELECT destination FROM forwardings WHERE source='%s'
hosts = 127.0.0.1
EOF

    cat <<EOF > /etc/postfix/mysql-virtual_mailboxes.cf
user = mail_admin
password = ${admin_password}
dbname = mail
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM users WHERE email='%s'
hosts = 127.0.0.1
EOF

    cat <<EOF > /etc/postfix/mysql-virtual_email2email.cf
user = mail_admin
password = ${admin_password}
dbname = mail
query = SELECT email FROM users WHERE email='%s'
hosts = 127.0.0.1
EOF

    cat <<EOF > /etc/postfix/mysql-virtual_transports.cf
user = mail_admin
password = ${admin_password}
dbname = mail
query = SELECT transport FROM transport WHERE domain='%s'
hosts = 127.0.0.1
EOF

chmod o= /etc/postfix/mysql-virtual_*.cf
chgrp postfix /etc/postfix/mysql-virtual_*.cf
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /home/vmail -m

postconf -e "myhostname = $(hostname)"
postconf -e 'mydestination = $myhostname, localhost, localhost.localdomain'
postconf -e 'mynetworks = 127.0.0.0/8'
postconf -e 'inet_interfaces = all'
postconf -e 'message_size_limit = 30720000'
postconf -e 'virtual_alias_domains ='
postconf -e 'virtual_alias_maps = proxy:mysql:/etc/postfix/mysql-virtual_forwardings.cf, #mysql:/etc/postfix/mysql-virtual_email2emai.cf'
postconf -e 'virtual_mailbox_domains = #proxy:mysql:/etc/postfix/mysql-virtual_domains.cf'
postconf -e 'virtual_mailbox_maps = proxy:mysql:/etc/postfix/mysql-virtual_mailboxes.cf'
postconf -e 'virtual_mailbox_base = /home/vmail'
postconf -e 'virtual_uid_maps = static:5000'
postconf -e 'virtual_gid_maps = static:5000'
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'broken_sasl_auth_clients = yes'
postconf -e 'smtpd_sasl_authenticated_header = yes'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_rbl_client zen.spamhaus.org, reject_rbl_client bl.spamcop.net, reject_rbl_client cbl.abuseat.org, check_policy_service unix:postgrey/socket, permit'
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtpd_tls_cert_file = /etc/pki/dovecot/certs/dovecot.pem'
postconf -e 'smtpd_tls_key_file = /etc/pki/dovecot/private/dovecot.pem'
postconf -e 'virtual_create_maildirsize = yes'
postconf -e 'virtual_maildir_extended = yes'
postconf -e 'proxy_read_maps = $local_recipient_maps $mydestination #$virtual_alias_maps $virtual_alias_domains $virtual_mailbox_maps $virtual_mailbox_domains $relay_recipient_maps $relay_domains $canonical_maps #$sender_canonical_maps $recipient_canonical_maps $relocated_maps $transport_maps #$mynetworks $virtual_mailbox_limit_maps'
postconf -e 'virtual_transport = dovecot'
postconf -e 'dovecot_destination_recipient_limit = 1'
postconf -e 'transport_maps = proxy:mysql:/etc/postfix/mysql-virtual_transports.cf'

if ! grep -qe "^dovecot$" "/etc/postfix/master.cf"; then
    cat <<EOF >> /etc/postfix/master.cf
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail:vmail argv=/usr/libexec/dovecot/deliver -f ${sender} -d ${recipient}

vacation     unix  -       n       n       -       -       pipe
  flags=Rhu user=vacation argv=/var/spool/vacation/vacation.php -f ${sender} -d ${recipient}
EOF
fi

systemctl stop sendmail.service
chkconfig sendmail off

systemctl enable postfix.service
systemctl start postfix.service

    echo "Configure Dovecot"
    if [ ! -f /etc/dovecot/dovecot.conf-backup ]; then
        cp -a /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf-backup
    fi

    cat <<EOF > /etc/dovecot/dovecot.conf
protocols = imap imaps pop3 pop3s
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_location = maildir:/home/vmail/%d/%n/Maildir

ssl_cert_file = /etc/pki/dovecot/certs/dovecot.pem
ssl_key_file = /etc/pki/dovecot/private/dovecot.pem

namespace private {
    separator = .
    prefix = INBOX.
    inbox = yes
}

protocol lda {
    log_path = /home/vmail/dovecot-deliver.log
    auth_socket_path = /var/run/dovecot/auth-master
    postmaster_address = postmaster@example.com
}

protocol pop3 {
    pop3_uidl_format = %08Xu%08Xv
}

auth default {
    user = root

    passdb sql {
        args = /etc/dovecot-sql.conf
    }

    userdb static {
        args = uid=5000 gid=5000 home=/home/vmail/%d/%n allow_all_users=yes
    }

    socket listen {
        master {
            path = /var/run/dovecot/auth-master
            mode = 0600
            user = vmail
        }

        client {
            path = /var/spool/postfix/private/auth
            mode = 0660
            user = postfix
            group = postfix
        }
    }
}

# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

EOF

    sed -i 's/#disable_plaintext_auth = no/disable_plaintext_auth = no/g' /etc/dovecot/conf.d/10-auth.conf
    grep "disable_plaintext_auth =" /etc/dovecot/conf.d/10-auth.conf

    #CHECK FIXME
    sed -i 's/auth_mechanisms = plain login login/auth_mechanisms = plain login/g' /etc/dovecot/conf.d/10-auth.conf
    grep "auth_mechanisms =" /etc/dovecot/conf.d/10-auth.conf

    cat <<EOF > /etc/dovecot-sql.conf
driver = mysql
connect = host=127.0.0.1 dbname=mail user=mail_admin password=${admin_password}
default_pass_scheme = CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';
EOF

    chgrp dovecot /etc/dovecot-sql.conf
    chmod o= /etc/dovecot-sql.conf

    systemctl enable dovecot.service
    systemctl start  dovecot.service

    newaliases
    systemctl restart postfix.service

    sed -i 's/mail_max_userip_connections = 10/mail_max_userip_connections = 20/g' /etc/dovecot/conf.d/20-imap.conf
    grep "mail_max_userip_connections" /etc/dovecot/conf.d/20-imap.conf

    #perms for apache
    usermod -a -G vmail apache
    chown vmail:vmail /home/vmail

    echo "Configure Greylisting"
    systemctl start postgrey.service
    systemctl reload postfix.service
    systemctl enable postgrey.service

    echo "Configure Webmail"
if [ ! -d /var/www/html/roundcube ]; then
	wget -O /var/www/html/roundcubemail.tar.gz /var/www/html http://sourceforge.net/projects/roundcubemail/files/roundcubemail/1.1.1/roundcubemail-1.1.1.tar.gz/download
	tar -C /var/www/html -zxf /var/www/html/roundcubemail.tar.gz
	rm -f /var/www/html/roundcubemail.tar.gz
	rm -Rf /var/www/html/roundcube/*
	mkdir /var/www/html/roundcube
	mv /var/www/html/roundcubemail-1.1.1/* /var/www/html/roundcube
	chown root:root -R /var/www/html/roundcube
	chmod 777 -R /var/www/html/roundcube/temp/
	chmod 777 -R /var/www/html/roundcube/logs/
fi

sed -e "s|mypassword|${admin_password}|" <<EOF | mysql -u root -p"${mysql_root_password}"
USE mysql;
GRANT USAGE ON * . * TO 'roundcube'@'localhost' IDENTIFIED BY 'mypassword';
CREATE DATABASE IF NOT EXISTS `roundcube`;
GRANT ALL PRIVILEGES ON `roundcube` . * TO 'roundcube'@'localhost';
FLUSH PRIVILEGES;
EOF

mysql -u root -p"${mysql_root_password}" 'roundcube' < /var/www/html/roundcube/SQL/mysql.initial.sql

cp /var/www/html/roundcube/config/config.inc.php.sample /var/www/html/roundcube/config/config.inc.php

sed -i "s|^\(\$rcmail_config\['default_host'\] =\).*$|\1 \'localhost\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['smtp_server'\] =\).*$|\1 \'localhost\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['smtp_user'\] =\).*$|\1 \'%u\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['smtp_pass'\] =\).*$|\1 \'%p\';|" /var/www/html/roundcube/config/config.inc.php
#sed -i "s|^\(\$rcmail_config\['support_url'\] =\).*$|\1 \'mailto:${E}\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['quota_zero_as_unlimited'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['preview_pane'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['read_when_deleted'\] =\).*$|\1 false;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['check_all_folders'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['display_next'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['top_posting'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['sig_above'\] =\).*$|\1 true;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['login_lc'\] =\).*$|\1 2;|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$rcmail_config\['db_dsnw'\] =\).*$|\1 \'mysqli://roundcube:${admin_password}@localhost/roundcube\';|" /var/www/html/roundcube/config/config.inc.php

rm -rf /var/www/html/roundcube/installer

systemctl reload httpd.service

    echo "Configure vacation emails"
useradd vacation
groupadd vacation

    cat <<EOF > /var/spool/vacation/vacation.php
   #!/usr/bin/php
<?php
$db_type = 'mysql';

# leave empty for connection via UNIX socket
$db_host = 'localhost';

# connection details
$db_username = 'mail_admin';
$db_password = '${admin_password}';
$db_name     = 'mail';

# path to logfile
$logfile = "/var/log/vacation/vacation.log";

# =========== end configuration ===========

$msg = json_encode($_SERVER);
#mail('adam.jimenez@gmail.com', 'autoreply', $msg);

$from = $_SERVER['argv'][2];
$to = $_SERVER['argv'][4];
$email = str_replace('auto-reply.', '', $to);

mysql_connect($db_host, $db_username, $db_password) or die('db failed');
mysql_select_db($db_name) or die('db select failed');

//check if already notified
$select = mysql_query("SELECT * FROM vacation_notification
    WHERE
        on_vacation = '".addslashes($email)."' AND
        notified = '".addslashes($from)."' AND
        notified_at > DATE_ADD(CURDATE(), INTERVAL -1 DAY);
");

if( mysql_num_rows($select) ){
    die("already notified\n");
}

mysql_query("INSERT INTO vacation_notification SET
    on_vacation = '".addslashes($email)."',
    notified = '".addslashes($from)."'
") or die(mysql_error());

$select_vacation = mysql_query("SELECT * FROM vacation
    WHERE
        email = '".addslashes($email)."' AND
        active = 1
    LIMIT 1
") or die(mysql_error());

$vacation = mysql_fetch_assoc($select_vacation);

if( !$vacation ){
    die("no vacation message\n");
    exit;
}

$headers = "From: $email\n";

mail($from, $vacation['subject'], $vacation['body'], $headers);

print "mail sent to $from\n";
EOF

if [ ! -d /var/spool/vacation ]; then
mkdir /var/spool/vacation
fi

chown -R vacation.vacation /var/spool/vacation
chmod 755 /var/spool/vacation/vacation.php

    cat <<EOF > /etc/postfix/mysql_vacation.cf
user = mail_admin
password = ${admin_password}
dbname = mail
table = users
select_field = CONCAT(SUBSTRING_INDEX(email,'@',1),'@auto-reply.',SUBSTRING_INDEX(email,'@',-1))
where_field = email
additional_conditions = and email IN (SELECT email from vacation WHERE active='1')
hosts = localhost
EOF

    postconf -e 'recipient_bcc_maps = mysql:/etc/postfix/mysql_vacation.cf'

    systemctl restart postfix.service

    echo "Configure Firewall"
    service firewalld start
    firewall-cmd --permanent --add-service=pop3s
    firewall-cmd --permanent --add-service=imaps
    firewall-cmd --permanent --add-service=smtp
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    systemctl start firewalld.service
else
	die "invalid server type"
fi
