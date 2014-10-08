#! /bin/bash

#Make sure we are running dropbear

if ! dpkg -l dropbears &> /dev/null
then
        exit 1
fi

dpkg -r dropbear || exit 1

/usr/bin/passwd -d root || exit 1

/usr/sbin/sendmail root <<EOF
Subject: SSH root access disabled

SSH and root has been disabled on OPI.

EOF
