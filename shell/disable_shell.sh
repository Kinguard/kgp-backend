#! /bin/bash

#Make sure we are running dropbear

if [  ! -x /usr/sbin/dropbear ]
then
        exit 1
fi

PKGS="dropbear-run dropbear-bin libtomcrypt1 libtommath1"

dpkg -P ${PKGS} || exit 1

/usr/bin/passwd -d root || exit 1

/usr/sbin/sendmail root <<EOF
Subject: SSH root access disabled

SSH and root has been disabled on unit.

EOF
