#! /bin/bash

# Check that we are not already running dropbear

if [ -x /usr/sbin/dropbear ]
then
	exit 1
fi

ARCH=$(dpkg --print-architecture)

dpkg -i /usr/share/opi-backend/*.deb || exit 1

PASSWORD=`/usr/bin/pwgen -n1 12`

echo "root:$PASSWORD" | /usr/sbin/chpasswd || exit 1

/usr/sbin/sendmail root <<EOF
Subject: SSH root access enabled

SSH and root has been enabled on unit.

Generated password for root is:

$PASSWORD

EOF
