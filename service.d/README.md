# services

Services to monitor are configured in this directory, a service is considered a set of filter/ipdetection rules along with a (set of) ports that
will be broadcast to all clients.

**NOTE** Ports are configured on the server not the clients

### Enabled

Is this service being monitored? - if set to 0 it will be parsed but will not be loaded into the server

### Protocol

Sent to remote clients as the protocol to use for the block 

### Ports

Sent to remote clients as the ports to block - **NOTE**  Service names such as pop3, ssh.... 
to be compatible with older devices that may not know all the names these will be sent to clients as their respective port numbers (110, 22...). 

### Timeout

How long after the first attempt to assume the IP has gone away and the IP is forgotten.
If this was set to 10m (or 600 seconds) then someone could forget their password and retry
every 11 minutes and only ever be counted as 1 hit.

### Attempts

How many hits without the timeout occuring before a block is sent.

### Block Expire

How long should a block last for. After this period the server will broadcast an unblock request
NOTE however that the client has a maximum time a block can last for after which it will auto expire
the block

### Long Attempts

If an attacker restarts attacking after the block expires how many blocks before we issue
a longer block.
Note this is number of blocks not number of hits, so they would get Attempts * Long Attempts before
we do a long block

## Long Block Timeout

How long to remember the attacker for after that initial block occured, if further blocks occur during
this time then they may be coinsidered for a long block

## Long Block Expire

Much like Block Expire but for a long block. This should be for a much longer period (they continue to annoy
us so lets ignore them for longer)

Note, if the long block expires before the long block time out the next block will be another long block


## Filters

What regex rules should be used to determine attackers? This should reference the name of a file in the 
filter.d directory without the extension which contains *failregex* line(s).

## IP Detection

What regex rules should be used to enter the filtering rules? This should reference the name of a file in the 
filter.d directory without the extension which contains *ipregex* line(s).


## Syslog

When a block is done make an additional log entry to this service in syslog. eg. if blocking an IP which is showing
up in the mail logs you may want to make a log entry in the mail logs showing that IP has been blocked so that
thoose reviewing those logs can see why the activity stopped.
