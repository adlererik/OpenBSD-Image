#!/bin/ksh



######################################################
###### BUILDS A FULL RELEASE IMAGE FOR OPENBSD #######
######################################################
###   This script will build a fully patched ISO   ###
###   for -stable branch with patched sets.        ###
###   The iso can be burned to a CD and used for   ###
###   installing on other machines. All compiled   ###
###   code is signed using OPENBSD's signify.      ###
###                                                ###
###   By Erik Adler aka Onryo.                     ###
###   GPG/PGP key ID: 0x2B4B58FE                   ###
######################################################
# BSD license                                        #
# Copyright (c) 2017 ERIK ADLER erik.adler@mensa.se  #
# aka Onryo                                          #
# GPG/PGP key ID: 0x2B4B58FE                         #
#                                                    #
# Permission to use, copy, modify, and distribute    #
# this software for any purpose with or without fee  #
# is hereby granted, provided that the above         #
# copyright notice and this permission notice appear #
# in all copies.                                     #
#                                                    #
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR    #
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS       #
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF       #
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL     #
# THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,      #
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES  #
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR     #
# PROFITS, WHETHER IN AN ACTION OF CONTRACT,         #
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT   #
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE    #
# OF THIS SOFTWARE.                                  #
######################################################
# Supports the following architectures as of 2017:   #  
# alpha amd64 armv7 hppa i386 landisk IO-DATA        #
# loongson luna88k macppc octeon sgi socppc sparc64  #
######################################################


# Full path to this script
scriptpath="/root/MakeISO.sh"

# Your cvs server of choice.
cvsserver="anoncvs@anoncvs.eu.openbsd.org"

# This is where builds end up. Need space here.
store=/root 

# using custom will enable tempfs in kernel
# export NAME=GENERIC.MP
export NAME=CUSTOM.MP

###################################

[[ -f "$scriptpath" ]] || { print \
          "Enter the correct name and path to this script"; exit 1; }
[[ $(id -u) = 0 ]] || { print "Must be root to run script"; exit 1; }

bsdver="OPENBSD_$(uname -r | tr . _)"
kernelcomp="$store/compileflag"
cores="$(sysctl hw.ncpufound)"
ver="$(uname -r | tr -d .)"
buildlog=/var/log


paths="/usr/bin:/bin:/usr/sbin:/sbin:/usr/X11R6/bin"
export PATH="$paths:/usr/local/bin:/usr/local/sbin"

# Setting NAME to CUSTOM.MP above will enable temfs RAM. This will
# speed up the compile time by mitigating ufs slow IOs.
# Be warned that data can be lost in case of a crash or
# power outage. Using GENERIC is recommend since OBSD 6.0

mkdir -p "$buildlog/buildlogs"

if [[ "$NAME" == "CUSTOM.MP" ]]; then
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

if [[ ! -f "$kernelcomp" ]]; then
    rm -f "$buildlog/buildlogs/*"

    cd /usr || { print "KERNEL failed to cd into usr"; exit 1; }
    if [[ ! -d src ]]; then
        cvs -d "$cvsserver:/cvs" checkout "-r$bsdver" -P src
    else
        { cd src && cvs up -Pd; } || { print \
           "KERNEL faild cd cvs up"; exit 1; }
    fi
    cd "/usr/src/sys/arch/$(machine)/conf" || { print \
                     "KERNEL failed cd conf"; exit 1; }
    cp GENERIC.MP CUSTOM.MP 
    if ! grep -q TMPFS CUSTOM.MP && [[ -f CUSTOM.MP ]]; then
        echo "option  TMPFS" >> CUSTOM.MP
    fi
    config "$NAME"
    cd "/usr/src/sys/arch/$(machine)/compile/$NAME" || { print \
                            "KERNEL faild cd to name"; exit 1; }
    make clean
    make "-j${cores#*=}" 2>&1 | tee "$buildlog/buildlogs/logfile_1_kernel"
    make install
    touch "$kernelcomp"
    echo "$scriptpath" > /etc/rc.firsttime
    mv "$buildlog/buildlogs/logfile_1_kernel" "$store/logfile_1_kernel"
    shutdown -r now
    sleep 30
else
    rm "$kernelcomp"
    mv "$store/logfile_1_kernel" "$buildlog/buildlogs/logfile_1_kernel"
fi

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_1_kernel" && { print \
                                      "build error on kernel"; exit 1; }

############ USERLAND #############

mkdir -p /usr/obj
{ cd /usr/obj && mkdir -p .old; } || { print \
      "USERLAND failed cd or mkdir"; exit 1; } 
touch dot && mv -- * .old && rm -rf .old & ### mv and delete in the background

mkdir -p /usr/src
{ cd /usr/src && make obj; } || { print "USERLAND ! cd or make obj"; exit 1; }
cd /usr/src/etc || { print "USERLAND failed to cd into etc"; exit 1; }
env DESTDIR=/ make distrib-dirs
cd /usr/src || { print "USERLAND failed to cd into src"; exit 1; }
make "-j${cores#*=}" build 2>&1 | tee "$buildlog/buildlogs/logfile_2_system"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_2_system" && { print \
                                    "build error on userland"; exit 1; }

########## SYSTEM XORG ############

{ cd /usr/xobj && mkdir -p .old; } || { print "XORG failed cd mkdir"; exit 1; }
touch dot && mv -- * .old && rm -rf .old &   ### deletes .old in the background

cd /usr || { print "XORG failed cd usr"; exit 1; }
if [[ ! -d xenocara ]]; then
    cvs -d "$cvsserver:/cvs" checkout "-r$bsdver" -P xenocara
else
    { cd /usr/xenocara && cvs up -Pd; } || { print \
               "XORG failed cd or cvs up"; exit 1; }
fi
cd /usr/xenocara || { print "XORG failed cd xenocara"; exit 1; }
make bootstrap
make obj

make "-j${cores#*=}" build 2>&1 | tee "$buildlog/buildlogs/logfile_3_xorg"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_3_xorg" && { print \
                               "build error in system xorg"; exit 1; }

######## CREATE WORK DIR ##########

export DESTDIR="$store/dest"
export RELEASEDIR="$store/rel"
[[ -d "$DESTDIR" ]] && mv "$DESTDIR" "$DESTDIR-"
[[ -d "$DESTDIR-" ]] && rm -rf "$DESTDIR-" &
mkdir -p "$DESTDIR" "$RELEASEDIR"

######### XENOCARA SETS ###########

cd /usr/xenocara || { print "XENO SET failed cd to xenocara"; exit 1; }
make release 2>&1 | tee "$buildlog/buildlogs/logfile_4_build_xeno_sets"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_4_build_xeno_sets" && \
                        { print "build error in xenocara sets"; exit 1; }

mv "$RELEASEDIR/SHA256" "$RELEASEDIR/SHA256_tmp" || { print \
                              "no SHA256_tmp made"; exit 1; }

########## SYSTEM SETS ############

cd /usr/src/etc || { print "SYS SETS failed cd etc"; exit 1; }
make release 2>&1 | tee "$buildlog/buildlogs/logfile_5_build_sys_sets"
cd /usr/src/distrib/sets || { print "SYS SETS failed cd set"; exit 1; }
sh checkflist
cat "$RELEASEDIR/SHA256_tmp" >> "$RELEASEDIR/SHA256"
rm -f "$RELEASEDIR/SHA256_tmp"

grep -rqF '* Error ' "$buildlog/buildlogs/logfile_5_build_sys_sets" && { print \
                                        "build error in system sets"; exit 1; }

###### MAKE RELEASE STRUCTURE #####

cd "$store" || { print "STRUCTURE failed cd store"; exit 1; }
test -d OpenBSD && mv OpenBSD OpenBSD- 
test -d OpenBSD- && rm -rf OpenBSD- & ### Delete old dir in background
mkdir "$store/OpenBSD"
mv "$RELEASEDIR" "$(machine)"
mkdir "$(uname -r)"
mv "$(machine)" "$(uname -r)/"
mv "$(uname -r)" OpenBSD/ || { print "STRUCTURE move into OpenBSD"; exit 1; }

####### SIGNING CHECKSUMS #########

cd "$store/OpenBSD/$(uname -r)/$(machine)" || { print \
               "SIGNING faild cd to machine"; exit 1; }
if [[ ! -f /etc/signify/stable-base.sec ]]; then
    print "Generate a private key"
    signify -G -p /etc/signify/stable-base.pub -s /etc/signify/stable-base.sec
else
    print "Using your old private key"
fi    
signify -S -s /etc/signify/stable-base.sec -m SHA256 -e -x SHA256.sig
ls -1 > index.txt
cp /etc/signify/stable-base.pub "$store/OpenBSD/$(uname -r)/"

########## BUILDING ISO ###########

cd /usr || { print "ISO failed to cd to usr"; exit 1; }
if [[ ! -d ports ]]; then
    cvs -d "$cvsserver:/cvs" checkout -r"${bsdver}" -P ports
else
    { cd ports && cvs up -Pd; } || { print "ISO failed cd or cvs"; exit 1; }
fi
cd /usr/ports/sysutils/cdrtools || { print "ISO failed cd cdrtools"; exit 1; }

if /usr/ports/infrastructure/bin/out-of-date | grep -q sysutils/cdrtools; then
    make update
    print "found update for cdrtools"
else
    make install
fi
cd "$store" || { print "ISO failed to cd into store"; exit 1; }
mkisofs -r -no-emul-boot -b "$(uname -r)/$(machine)/cdbr" -c boot.catalog -o \
    "install${ver}.iso" "$store/OpenBSD"

####### CHECKING BUILD LOGS #######

print "Checking build logs for errors"
if  grep -rF '* Error ' "$buildlog/buildlogs/"; then
    print "Try deleting src xenocara src and ports and running script again."
    print "CVS source code could be corrupt. Are paths set correctly?"
else
    v="$(sysctl -n kern.version)"; v="${v#* }"; v="${v%% *}"
    print "NO ERRORS FOUND IN BUILD LOGS"
    print "YOU ARE TRACKING $v"
fi
