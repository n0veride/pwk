
List block devices.  


**-A**, **--noempty**  
Don’t print empty devices.  
  
**-a**, **--all**  
Disable all built-in filters and list all empty devices and  
RAM disk devices too.  
  
**-b**, **--bytes**  
Print the sizes in bytes rather than in a human-readable  
format.  
  
By default, the unit, sizes are expressed in, is byte, and  
unit prefixes are in power of 2^10 (1024). Abbreviations of  
symbols are exhibited truncated in order to reach a better  
readability, by exhibiting alone the first letter of them;  
examples: "1 KiB" and "1 MiB" are respectively exhibited as  
"1 K" and "1 M", then omitting on purpose the mention "iB",  
which is part of these abbreviations.  
  
**-D**, **--discard**  
Print information about the discarding capabilities (TRIM,  
UNMAP) for each device.  
  
**-d**, **--nodeps**  
Do not print holder devices or slaves. For example, **lsblk**  
**--nodeps /dev/sda** prints information about the sda device  
only.  
  
**-E**, **--dedup** _column_  
Use _column_ as a de-duplication key to de-duplicate output  
tree. If the key is not available for the device, or the  
device is a partition and parental whole-disk device provides  
the same key than the device is always printed.  
  
The usual use case is to de-duplicate output on system  
multi-path devices, for example by **-E WWN**.  
  
**-e**, **--exclude** _list_  
Exclude the devices specified by the comma-separated _list_ of  
major device numbers. Note that RAM disks (major=1) are  
excluded by default if **--all** is not specified. The filter is  
applied to the top-level devices only. This may be confusing  
for **--list** output format where hierarchy of the devices is  
not obvious.  
  
**-f**, **--fs**  
Output info about filesystems. This option is equivalent to  
**-o NAME,FSTYPE,FSVER,LABEL,UUID,FSAVAIL,FSUSE%,MOUNTPOINTS**.  
The authoritative information about filesystems and raids is  
provided by the [blkid(8)](https://man7.org/linux/man-pages/man8/blkid.8.html) command.  
  
**-I**, **--include** _list_  
Include devices specified by the comma-separated _list_ of  
major device numbers. The filter is applied to the top-level  
devices only. This may be confusing for **--list** output format  
where hierarchy of the devices is not obvious.  
  
**-i**, **--ascii**  
Use ASCII characters for tree formatting.  
  
**-J**, **--json**  
Use JSON output format. It’s strongly recommended to use  
**--output** and also **--tree** if necessary.  
  
**-l**, **--list**  
Produce output in the form of a list. The output does not  
provide information about relationships between devices and  
since version 2.34 every device is printed only once if  
**--pairs** or **--raw** not specified (the parsable outputs are  
maintained in backwardly compatible way).  
  
**-M**, **--merge**  
Group parents of sub-trees to provide more readable output  
for RAIDs and Multi-path devices. The tree-like output is  
required.  
  
**-m**, **--perms**  
Output info about device owner, group and mode. This option  
is equivalent to **-o NAME,SIZE,OWNER,GROUP,MODE**.  
  
**-N**, **--nvme**  
Output info about NVMe devices only.  
  
**-v**, **--virtio**  
Output info about virtio devices only.  
  
**-n**, **--noheadings**  
Do not print a header line.  
  
**-o**, **--output** _list_  
Specify which output columns to print. Use **--help** to get a  
list of all supported columns. The columns may affect  
tree-like output. The default is to use tree for the column  
'NAME' (see also **--tree**).  
  
The default list of columns may be extended if _list_ is  
specified in the format _+list_ (e.g., **lsblk -o +UUID**).  
  
**-O**, **--output-all**  
Output all available columns.  
  
**-P**, **--pairs**  
Produce output in the form of key="value" pairs. The output  
lines are still ordered by dependencies. All potentially  
unsafe value characters are hex-escaped (\x\<code\>). See also  
option **--shell**.  
  
**-p**, **--paths**  
Print full device paths.  
  
**-r**, **--raw**  
Produce output in raw format. The output lines are still  
ordered by dependencies. All potentially unsafe characters  
are hex-escaped (\x\<code\>) in the NAME, KNAME, LABEL,  
PARTLABEL and MOUNTPOINT columns.  
  
**-S**, **--scsi**  
Output info about SCSI devices only. All partitions, slaves  
and holder devices are ignored.  
  
**-s**, **--inverse**  
Print dependencies in inverse order. If the **--list** output is  
requested then the lines are still ordered by dependencies.  
  
**-T**, **--tree**\[**=**_column_\]  
Force tree-like output format. If _column_ is specified, then a  
tree is printed in the column. The default is NAME column.  
  
**-t**, **--topology**  
Output info about block-device topology. This option is  
equivalent to  
  
**-o**  
**NAME,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,RA,WSAME**.  
  
**-h**, **--help**  
Display help text and exit.  
  
**-V**, **--version**  
Print version and exit.  
  
**-w**, **--width** _number_  
Specifies output width as a number of characters. The default  
is the number of the terminal columns, and if not executed on  
a terminal, then output width is not restricted at all by  
default. This option also forces **lsblk** to assume that  
terminal control characters and unsafe characters are not  
allowed. The expected use-case is for example when **lsblk** is  
used by the [watch(1)](https://man7.org/linux/man-pages/man1/watch.1.html) command.  
  
**-x**, **--sort** _column_  
Sort output lines by _column_. This option enables **--list**  
output format by default. It is possible to use the option  
**--tree** to force tree-like output and than the tree branches  
are sorted by the _column_.  
  
**-y**, **--shell**  
The column name will be modified to contain only characters  
allowed for shell variable identifiers, for example, MIN_IO  
and FSUSE_PCT instead of MIN-IO and FSUSE%. This is usable,  
for example, with **--pairs**. Note that this feature has been  
automatically enabled for **--pairs** in version 2.37, but due to  
compatibility issues, now it’s necessary to request this  
behavior by **--shell**.  
  
**-z**, **--zoned**  
Print the zone related information for each device.  
  
**--sysroot** _directory_  
Gather data for a Linux instance other than the instance from  
which the **lsblk** command is issued. The specified directory is  
the system root of the Linux instance to be inspected. The  
real device nodes in the target directory can be replaced by  
text files with udev attributes.