#!/bin/sh



[ -d $buildlog/buildlogs ] && umount $buildlog/buildlogs
[ -d /usr/obj ] && umount /usr/obj
[ -d /usr/xobjj ] && umount /usr/xobj
