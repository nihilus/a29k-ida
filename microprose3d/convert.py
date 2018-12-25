#!/usr/bin/python
# https://github.com/mamedev/mame/blob/83bc05a08b672bd602370818dfde9bfa06d373f5/src/mame/drivers/micro3d.cpp
from zipfile import ZipFile
from itertools import chain

mame_spec = [ ("f15se.zip", ["122.dth", "125.dth", "123.dth", "124.dth",
    "118.dth", "121.dth", "119.dth", "120.dth"],"f15se_drmath.bin") , 
        ("botss.zip" ,[ "110-00013-122.u134", "110-00013-125.u126", "110-00013-123.u114",
        "110-00013-224.u107", "110-00013-118.u135", "110-00013-121.u127",
        "110-00013-219.u115", "110-00013-120.u108" ],"botss_drmath.bin") , 
        ("tankbatl.zip" ,[ "s24e_u.134", "s16e_u.126", "s08e_u.114", "s00e_u.107",
            "s24o_u.135", "s16o_u.127", "s08o_u.115", "s00o_u.108" ], "tankbatl_drmath.bin") ]

for (zipfile,roms,dest) in mame_spec:
    with ZipFile(zipfile,'r') as myzip:
        data = map(lambda x: myzip.open(x).read(),roms)
        with open(dest, 'w') as outfile:
            outfile.write(''.join(list(chain(*zip(*data)))))
        

