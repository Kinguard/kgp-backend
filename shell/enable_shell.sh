#! /bin/bash

# Check that we are not already running dropbear

if [ -x /usr/sbin/dropbear ]
then
	exit 1
fi

dpkg -i /usr/share/opi-backend/dropbear_2014.65-1ubuntu1_armhf.deb || exit 1

PASSWORD=`/usr/bin/pwgen -n1 12`

echo "root:$PASSWORD" | /usr/sbin/chpasswd || exit 1

/usr/sbin/sendmail root <<EOF
Subject: SSH root access enabled

SSH and root has been enabled on OPI.

Generated password for root is:

$PASSWORD

EOF
