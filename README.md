## About

This module is a POC of the Linux kernel "move to trash" implementation

## Usage

Given the compiled module:

1. Use `insmod fstrash.ko` to load the module
2. Use `mkdir /.fstrash` to create the trash folder
3. ... run `find /.fstrash -iname XXX_* -mmin 5 exec rm -f {} \;` or similar by the CRON
4. Use `rmdir -rf /.fstrash` to remove the trash folder
5. Use `rmmod fstrash` to unload the module

## Credits

Written by Ilya V. Matveychikov <i.matveychikov@securitycode.ru>, distributed under GPL
