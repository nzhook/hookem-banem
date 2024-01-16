# Upgrading Hookem-banem
Changes between versions of hookem-banem:

## Upgrading from the 2019 version (7be5117)
### Config files
Settings can now be stored in a config directory with the extension .conf

For hookem-client the default directory is **$0.d** (eg. hookem-client.pl.d)

For hookem-server the default directory is **/usr/local/etc/hookem-banem/conf.d**

If you had previously modified one of the setting values it is recommended to move these to a separate file and remove the 'my' in front.

eg.
If you had something like this in the hookem-client.pl
```
my $checksumsalt = "Secrets0fM4gic";
...
my $myparent = "210.48.108.14";
```

You can now put this in hookem-client.pl.d/local.conf:
```
$checksumsalt = "Secrets0fM4gic";
$myparent = "210.48.108.14";
```
And then overwrite the old hookem-client.pl script with the new one

### iptables vs ipset
The 2019 version of hookem-client used separate iptables tables for blocking by default, the tables were named hookem-INP\<service\>.
Newer versions use iptables and ipset for a much faster and cleaner looking method.

When upgrading to ipset the old version may not remove the old tables automatically (due to a bug), you can do this yourself using the commands:
```
iptables -F hookem-INP\<service\>
iptables -X hookem-INP\<service\>
```

This can be done once the new version starts up

If you would prefer to stay with the older method you can use the config file located in example_config/client_iptables.pl.conf

If you used custom blocking commands you can move these into a config file

### cache_block command now has parsing
Previously hookem-client had a cache_block command which was used to pull all the existing rules from the table in case something changed
However, it needed to provide the list of IP addresses which sometimes meant sending the command to another one first.

The new versions add parse_block which is a regex to extract the IP address from the cache_block output. If you had modified the commands
you should now add parse_block. The first substring match of the regex (part in brackets) is expected to be the IP address.

Example using iptables:

If the results of the **cache_block** command: **/sbin/iptables -nL hookem-INP\<service\>**
```
Chain hookem-INPtestservice (1 references)
target     prot opt source               destination
DROP       all  --  100.200.300.10       0.0.0.0/0
DROP       all  --  200.100.300.50       0.0.0.0/0
DROP       all  --  10.20.30.100         0.0.0.0/0
```

**parse_block** would be set to: **qw(DROP\s.\*--\s\*([0-9a-f:.]+))**

which matches on the following:
```
>>DROP<<       all  >>--<<  (>>100.200.300.10<<)       0.0.0.0/0
```

NOTE: the default is now ipset which has a different output so requires a different **parse_block**
