#!/bin/sh



###                              POSIX QEFS                                ###
###                                                                        ###
##############################################################################
################## BUILDS A FULL RELEASE IMAGE FOR OPENBSD ###################
##############################################################################
###                                                                        ###
### This script will build a fully patched ISO for -stable branch with     ###
### patched sets. The iso can be burned to a CD and used for installing on ###
### other machines. All compiled code is signed using OPENBSD's signify.   ###
###                                                                        ###
###  By Erik Adler aka Onryo.                                              ###
###  GPG/PGP key ID: 0x2B4B58FE                                            ###
###                                                                        ###
##############################################################################
#                                                                            #
# BSD license                                                                #
# Copyright (c) 2017 ERIK ADLER erik.adler@mensa.se                          #
# aka Onryo                                                                  #
# GPG/PGP key ID: 0x2B4B58FE                                                 #
#                                                                            #
# Permission to use, copy, modify, and distribute this software for any      #
# purpose with or without fee is hereby granted, provided that the above     #
# copyright notice and this permission notice appear in all copies.          #
#                                                                            #
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES   #
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF           #
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR    #
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES     #
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN      #
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF    #
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.             #
#                                                                            #
##############################################################################
# Supports the following architectures as of 2017:                           #
# alpha amd64 armv7 hppa i386 landisk IO-DATA loongson luna88k macppc octeon #
# sgi socppc sparc64                                                         #
##############################################################################


# Full path to this script.
# Auto detection is a bad idea.
scriptpath=/root/MakeISO.sh

# Your cvs server of choice.
cvsserver=anoncvs@anoncvs.eu.openbsd.org

# This is where build ends up
# You can use the path to your home dir
store=/root

# Your name or nick used for the signing
# generated signify keys.
myname='erik adler'

# using custom will enable tempfs in kernel
export NAME=GENERIC.MP
# export NAME=CUSTOM.MP

###################################

[ -f "$scriptpath" ] || { printf \
           'Enter the correct name and path to this script\n'; exit 1; }
[ "$(id -u)" = 0 ] || { printf 'Must be root to run script\n'; exit 1; }

buildlog=/var/log
bsdver="OPENBSD_$(uname -r | tr . _)"
kernelcomp="$store/compileflag"
cores="$(sysctl hw.ncpufound)"
ver="$(uname -r | tr -d .)"
finger="$(ssh-keygen -E MD5 -l -F "${cvsserver#*@}" \
               |grep MD5 || echo 'BEING ANALYZED')"

paths="/usr/bin:/bin:/usr/sbin:/sbin:/usr/X11R6/bin"
export PATH="$paths:/usr/local/bin:/usr/local/sbin"

mkdir -p "$store"
mkdir -p "$buildlog/buildlogs"

# Setting NAME to CUSTOM.MP above will enable temfs RAM. This will
# speed up the compile time by mitigating ufs slow IOs.
# Be warned that data can be lost in case of a crash or
# power outage. Using GENERIC is recommend since OBSD 6.0

if [ "$NAME" = CUSTOM.MP ]; then
    if  df | grep -q tmpfs; then
        umount "$buildlog/buildlogs"
        umount /usr/obj
        umount /usr/xobj
    fi
    mount -t tmpfs tmpfs "$buildlog/buildlogs"
    mount -t tmpfs tmpfs /usr/obj
    mount -t tmpfs tmpfs /usr/xobj
    fi

############# KERNEL ##############

if [ ! -f "$kernelcomp" ]; then
    rm -f "$buildlog/buildlogs/*"

    cd /usr || exit 1;
    if [ ! -s src/CVS/Root ]; then
        clear && printf '\nRepository in use:\n%s\n\n' "$finger"
        printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
        printf '%s\n\n' 'Populating local src code tree. Will take some time'
        cvs -qd "$cvsserver:/cvs" checkout -r "$bsdver" -P src
    else
        clear && printf '\nRepository in use:\n%s\n\n' "$finger"
        printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
        printf '\n%s\n\n' 'Looking for src changes (cvs up). Will take some time'
        { cd src && cvs -d "$cvsserver:/cvs" -q up -r "$bsdver" -Pd; } || exit 1;
    fi
    cd "/usr/src/sys/arch/$(machine)/conf" || exit 1;
    cp GENERIC.MP CUSTOM.MP
    if ! grep -q TMPFS CUSTOM.MP && [ -f CUSTOM.MP ]; then
        echo "option  TMPFS" >> CUSTOM.MP
    fi
    config "$NAME"
    cd "/usr/src/sys/arch/$(machine)/compile/$NAME" || exit 1;
    make clean
    make "-j${cores#*=}" 2>&1 | tee "$buildlog/buildlogs/logfile_1_kernel"
    make install
    touch "$kernelcomp"
    echo "$scriptpath" > /etc/rc.firsttime
    mv "$buildlog/buildlogs/logfile_1_kernel" "$store/logfile_1_kernel"
    shutdown -r now
    exit
else
    rm "$kernelcomp"
    mv "$store/logfile_1_kernel" "$buildlog/buildlogs/logfile_1_kernel"
fi

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_1_kernel" && exit 1;

############ USERLAND #############

mkdir -p /usr/obj
{ cd /usr/obj && mkdir -p .old; } || exit 1;
touch dot && mv -- * .old && rm -rf .old & ### mv and delete in the background

mkdir -p /usr/src
{ cd /usr/src && make obj; } || exit 1;
cd /usr/src/etc || exit 1;
env DESTDIR=/ make distrib-dirs
cd /usr/src || exit 1;
make "-j${cores#*=}" build 2>&1 | tee "$buildlog/buildlogs/logfile_2_system"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_2_system" && exit 1;

########## SYSTEM XORG ############

{ cd /usr/xobj && mkdir -p .old; } || exit 1;
touch dot && mv -- * .old && rm -rf .old &   ### deletes .old in the background

cd /usr || exit 1;
if [ ! -s xenocara/CVS/Root ]; then
    printf '\nRepository in use:\n%s\n\n' "$finger"
    printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
    printf '%s\n\n' 'Populating local xeno code tree. Will take some time'
    cvs -d "$cvsserver:/cvs" checkout -r "$bsdver" -P xenocara
else
    printf '\nRepository in use:\n%s\n\n' "$finger"
    printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
    printf '\n%s\n\n' 'Looking for xeno changes (cvs up). Will take some time'
    { cd xenocara && cvs -d "$cvsserver:/cvs" -q up -r "$bsdver" -Pd; } || exit 1;
fi
cd /usr/xenocara || exit 1;
make bootstrap
make obj

make "-j${cores#*=}" build 2>&1 | tee "$buildlog/buildlogs/logfile_3_xorg"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_3_xorg" && exit 1;

######## CREATE WORK DIR ##########

export DESTDIR="$store/dest"
export RELEASEDIR="$store/rel"
[ -d "$DESTDIR" ] && mv "$DESTDIR" "$DESTDIR-"
[ -d "$DESTDIR-" ] && rm -rf "$DESTDIR-" &
mkdir -p "$DESTDIR" "$RELEASEDIR"

########## SYSTEM SETS ############

cd /usr/src/etc || exit 1;
make release 2>&1 | tee "$buildlog/buildlogs/logfile_4_build_sys_sets"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_4_build_sys_sets" && exit 1;

######### XENOCARA SETS ###########

cd /usr/xenocara || exit 1;
make release 2>&1 | tee "$buildlog/buildlogs/logfile_5_build_xeno_sets"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_5_build_xeno_sets" && exit 1;

###### MAKE RELEASE STRUCTURE #####

cd "$store" || exit 1;
[ -d OpenBSD ] && mv OpenBSD OpenBSD-
[ -d OpenBSD- ] && rm -rf OpenBSD- & ### Delete old dir in background
mkdir "$store/OpenBSD"
mv "$RELEASEDIR" "$(machine)"
mkdir "$(uname -r)"
mv "$(machine)" "$(uname -r)/"
mv "$(uname -r)" OpenBSD/ || exit 1;

########## BUILDING ISO ###########

cd /usr || exit 1;
if [ ! -s ports/CVS/Root ]; then
    printf '\nRepository in use:\n%s\n\n' "$finger"
    printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
    printf '%s\n\n' 'Populating local port code tree. Will take some time'
    cvs -d "$cvsserver:/cvs" checkout -r "$bsdver" -P ports
else
    printf '\nRepository in use:\n%s\n\n' "$finger"
    printf '%s\n' 'Fingerprints listed: https://www.openbsd.org/anoncvs.html'
    printf '\n%s\n\n' 'Looking for ports changes (cvs up). Will take some time'
    { cd ports && cvs -d "$cvsserver:/cvs" -q up -r "$bsdver" -Pd; } || exit 1;
fi
cd /usr/ports/sysutils/cdrtools || exit 1;

if /usr/ports/infrastructure/bin/out-of-date | grep -q sysutils/cdrtools; then
    make update
    printf '\n%s\n\n' 'Found update for cdrtools'
else
    make install
fi
cd "$store" || exit 1;

mkisofs -r -no-emul-boot -b "$(uname -r)/$(machine)/cdbr" -c boot.catalog -o \
  "$store/OpenBSD/$(uname -r)/$(machine)/install${ver}.iso" "$store/OpenBSD"

####### SIGNING CHECKSUMS #########

cd "$store/OpenBSD/$(uname -r)/$(machine)" || exit 1;
[ ! -f SHA256 ] || rm SHA256
sha256 -- * > SHA256
if [ ! -f /etc/signify/stable-base.sec ]; then
   key="my-openbsd-$(uname -r)-base"
   printf '\n%s\n\n' 'Generate a private key. Do not forget your password'
   signify -G -c "$myname openbsd $(uname -r) base" -p "/etc/signify/$key.pub" \
                                                    -s "/etc/signify/$key.sec"
else
    printf '\n%s\n\n' 'Using your old private key'
fi
signify -S -s "/etc/signify/$key.sec" -m SHA256 -e -x SHA256.sig

for f in *; do ### avoids using ls -l
    [ -e "$f" ] || continue; echo "$f" >> index.txt
done

cp "/etc/signify/$key.pub" "$store/OpenBSD/"

####### CHECKING BUILD LOGS #######

printf '\n%s\n\n' 'CHECKING BUILD LOGS FOR ERRORS'
if  grep -rF '* Error ' $buildlog/buildlogs/; then
    printf '%s\n\n' 'Try deleting src xenocara src and ports. Run script again.'
    printf '%s\n\n' 'CVS source code could be corrupt. Are paths set correctly?'
else
    v=$(sysctl -n kern.version); v=${v#* }; v=${v%% *}
    printf '%s\n\n' 'NO ERRORS FOUND IN BUILD LOGS'
    printf 'YOU ARE TRACKING %s\n\n' "$v"
fi
