#! /bin/bash

#Make sure we are running dropbear

if [  ! -x /usr/sbin/dropbear ]
then
        exit 1
fi

dpkg -P dropbear-bin dropbear-run || exit 1

/usr/bin/passwd -d root || exit 1

/usr/sbin/sendmail root <<EOF
Subject: SSH root access disabled

SSH and root has been disabled on unit.

EOF
