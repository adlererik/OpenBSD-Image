#!/bin/ksh

######################################################
###### BUILDS A FULL RELEASE IMAGE FOR OPENBSD #######
######################################################
###   This script will build a fully patched ISO   ###
###   with patched sets and patched source code.   ###
###   The iso can be burned to a CD and used for   ###
###   installing on other machines. All compiled   ###
###   code is signed using OPENBSD's signify.      ###
###                                                ### 
###   By Erik Adler aka Onryo.                     ###
###   GPG/PGP key ID: 0x2B4B58FE                   ###
######################################################
# BSD license                                        #
# Copyright (c) 2014 ERIK ADLER erik.adler@mensa.se  #
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
# Supports the following architectures as of 2014:   #   
# alpha amd64 arm armish armv7 aviion hppa hppa64    #
# i386 ia64 landisk loongson luna88k m88k macppc     #
# mips64 octeon powerpc sgi sh socppc solbourne      # 
# sparc sparc64 vax zaurus                           #
######################################################

CORES=$(sysctl hw.ncpufound)
BUILDLOG=/var/log
mkdir -p ${BUILDLOG}/buildlogs
# Using the following ram tmpfs while building will 
# speed up the compile time by mitigating ufs slow IOs.
# Be warned that data can be lost in case of a crash or 
# power outage.  
mount -t tmpfs tmpfs ${BUILDLOG}/buildlogs 
mount -t tmpfs tmpfs /usr/obj

export NAME=GENERIC.MP
#export NAME=GENERIC

#### 1. BUILD AND INSTALL A NEW KERNEL 
##############################################
# This will build a kernel for the architecture 
# from above. MP is for multiprocessor.

cd /usr/src/sys/arch/`machine`/conf 
config ${NAME} 
cd /usr/src/sys/arch/`machine`/compile/${NAME} 
make clean 
make -j${CORES#*=} 2>&1 | tee ${BUILDLOG}/buildlogs/logfile_1_build_kernel
make install 
# shutdown -r now


#### 2. BUILD AND INSTALL SYSTEM  
##############################################
# After this step we will now be running the
# built system from this step. 

cd /usr/obj 

mkdir -p old_obj #Safely delete old objs in backgroupd with & 
mv * old_obj
rm -rf old_obj & 

cd /usr/src
make obj 
cd /usr/src/etc 
env DESTDIR=/ make distrib-dirs
cd /usr/src 
make -j${CORES#*=} build 2>&1 | tee ${BUILDLOG}/buildlogs/logfile_2_build_system


#### 3. MAKE THE SYSTEM RELEASE AND VALIDATE 
##############################################
# In the last step we built the system that is
# now running. We now will build our release  
# sets for system and put them in the RELEASEDIR. 
# base55.tgz, comp55.tgz, etc55.tgz game55.tgz
# man55.tgz 

export DESTDIR=/root/dest
export RELEASEDIR=/root/rel

test -d ${DESTDIR} 
mv ${DESTDIR} ${DESTDIR}.old     #  safely deletes OLD DESTDIR in bkground & 
rm -rf ${DESTDIR}.old &                  
mkdir -p ${DESTDIR} ${RELEASEDIR}   

cd /usr/src/etc 
make release 2>&1 | tee ${BUILDLOG}/buildlogs/logfile_3_sys_release 
cd /usr/src/distrib/sets 
sh checkflist 
cd ${RELEASEDIR}
mv SHA256 SHA256_temp


#### 4. BUILD AND INSTALL XENOCARA  
##############################################
# In this step we will build and install the
# X windows. This will be installed in /usr/X11R6

cd /usr/xobj 
mkdir -p old_xobj 
mv * old_xobj 
rm -rf old_xobj & 

cd /usr/xenocara
make bootstrap 
make obj 
make -j${CORES#*=} build 2>&1 | tee ${BUILDLOG}/buildlogs/logfile_4_build_xenocara


#### 5. MAKE THE SYSTEM RELEASE AND VALIDATE 
##############################################
# In the last step we built xenocara (X.org) 
# We now will build our release sets for X 
# windows. These sets will be added with the 
# system sets in the RELEASEDIR. 
# xbase55.tgz xetc.tgz xfont55.tgz xserv55.tgz
# xshare55.tgz. 
 
test -d ${DESTDIR} 
mv ${DESTDIR} ${DESTDIR}.old 
rm -rf ${DESTDIR}.old & 
mkdir -p ${DESTDIR} ${RELEASEDIR}

cd /usr/xenocara # build inside /usr/xenocara
make release 2>&1 | tee ${BUILDLOG}/buildlogs/logfile_5_xenocara_release
cd ${RELEASEDIR}
cat SHA256 >> SHA256_temp && mv SHA256_temp SHA256


#### 6. ORGANIZE TO RELEASE STRUCTURE
##############################################
# In this step the sets will be organized
# into the same structure found on the images
# CDs ie OpenBSD/5.6/amd64.

export IMGROOT=/root
cd ${IMGROOT}
test -d OpenBSD && mv OpenBSD OpenBSD.previous
mkdir -p ${IMGROOT}/OpenBSD

mv ${RELEASEDIR} `machine`
mkdir `uname -r`
mv `machine` `uname -r`/
mv `uname -r` OpenBSD/

cd ${IMGROOT}/OpenBSD/`uname -r`
tar zcf src_stable_errata.tar.gz /usr/src
tar zcf xenocara_stable_errata.tar.gz /usr
tar zcf ports_stable.tar.gz /usr
tar zcf buildlogs.tar.gz ${BUILDLOG}/buildlogs
cksum -a SHA256 *.gz > SHA256


#### 7. SIGN ALL SETS USING OUR OWN KEY
##############################################
# We use OpenBSD signify to make a private key
# if we don't have one. Then we will sign our 
# sets so we later can verify they have not been
# tampered with. If you have not already made a 
# private key then uncomment the key generator.
# The patched code is also signed and archived.

cd ${IMGROOT}/OpenBSD/`uname -r`/`machine`
#echo "Generate key pair to sign your release with."
#signify -G -p /etc/signify/rolled-stable-base.pub -s /etc/signify/rolled-stable-base.sec
echo "Sign your sets with your key."
signify -S -s /etc/signify/rolled-stable-base.sec -m SHA256 -e -x SHA256.sig
ls -1 > index.txt
cd ${IMGROOT}/OpenBSD/`uname -r`
echo "Sign your patched source with your key."
signify -S -s /etc/signify/rolled-stable-base.sec -m SHA256 -e -x SHA256.sig
ls -1 > index.txt

#### 8. ISO IMAGE THAT CAN BE BURNED TO DISK 
##############################################
# This will make an iso with the sets in the 
# correct places for installing from disk. The image 
# is a fully patched OS that is signed with your 
# own key. Your patched source code is included 
# and signed also. When new errata patches are
# released just add them to your source repos.

export PKG_PATH=http://ftp.eu.openbsd.org/pub/OpenBSD/`uname -r`/packages/`machine`
pkg_add cdrtools
cd ${IMGROOT}
mkisofs -r -no-emul-boot -b `uname -r`/`machine`/cdbr -c boot.catalog -o install-full.iso ${IMGROOT}/OpenBSD

# clean up.
##############################################
cd ${BUILDLOG}/buildlogs && mkdir -p tmp_logs && mv * tmp_logs
rm -rf tmp_logs &
unset RELEASEDIR DESTDIR IMGROOT PKG_PATH CORES NAME BUILDLOG
