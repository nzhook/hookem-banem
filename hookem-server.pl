#!/usr/bin/perl
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
use warnings;
use Data::Dumper;
use Socket;
use Socket6;
use POSIX ":sys_wait_h";
use IO::Socket::INET;
use Digest::MD5 qw(md5_hex);
use POSIX qw(mktime);
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

# Replacement for fail2ban with a design toward handling
# large log files from multiple servers and distrubted blocking
#
# nzHook - September 2013

# Future features:
#   - Support for filter functions (eg. to pull just the request string from an apache log)
#   - Command line tools for manual ban and unban
#   - Defined config path
#   - Rather than ban at the time, queue the bans assess for netblocks/patterns and run the queue every second
#   - Support for tailing a log
#   - Ignore log entries which are old (could be used with warmtime)
#   - For $havebigsubnetscounter, have two modes... Dont block just analyse, then block on alarm, OR Just block, analyse on alarm - both have their advantages
#   - Specify the IP(s) to send requests over

# Debug level, the higher the value the more detail sent to the debug file
my $debug = 2;
my %filtercfg;
my %ipfindcfg;

# Sep  4 00:08:45 trible rpc.mountd[2167]: libnss-mysql: Connection ...
my $log_format = '^(?P<datetime>[a-zA-Z]{3} +[0-9]+ [0-9]+:[0-9]+:[0-9]+) (?P<server>[a-z0-9.]+) (?P<message>\S+: .*)';
# Sep  6 00:24:17
my $log_dateformat = '^(?P<month>[a-zA-Z]{3}) +(?P<day>[0-9]+) (?P<hour>[0-9]+):(?P<minute>[0-9]+):(?P<second>[0-9]+)';

# If the month shows up in this list it is replaced with the value (note: use Human, we convert to perl)
my %log_datemonths = ( "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12 );

my $warmtime = 3;			# Wait this many seconds before doing any bans (eg. allow time to catch up) - NOTE: This will still assume an IP has been banned
my $cooloff  = 2;			# Wait this many seconds after a ban before attempting it again
my $bport = 2008;			# The UDP port the clients listen on to receieve the broadcasted requests
my @broadcast_ips = ( "255.255.255.255", "210.48.255.255" );	# The IPs to broadcast to (will send to each in the array)
my $checksumsalt = "AnyOn3H3re2L!st3n";	# The salt which checksums will be made with (must be the same on each client)
#my $firstsubnetsize = 3;		# When working out subnets to block, ignore the last X values (eg. 3 would a /29)
#my $firstsubnetallow = 4;		# Based on $firstsubnetsize, how many of the subnets should trigger a whole subnet ban (4 here would = 50% of a /29 prefix as each 3 bits is 8 prefixes)
my $firstsubnetsize = 4;		# When working out subnets to block, ignore the last X values (eg. 3 would a /29)
my $firstsubnetallow = int(2 ** $firstsubnetsize * 0.25);		# Based on $firstsubnetsize, how many of the subnets should trigger a whole subnet ban (4 here would = 50% of a /29 prefix as each 3 bits is 8 prefixes)

my $doserverfirst = 0;			# When an attack starts, setting this to 1 will send the first block request only to the server being hit (the next block will be done via broadcast)

# @TODO need to find an example of this (or our value in the syslog-ng config)
#my $log_format = '^(?P<facility>[a-z]*)\.(?P<priority>[a-z]*) (?P<datetime>[a-zA-Z]{3} +[0-9]* [0-9]*:[0-9]*:[0-9]*) (?P<server>[a-z0-9.]+) (?P<message>\S+: .*)';

my @ignoreips = ("210.48.108.1");	# Array of IPs to ignore (office, load balancers, jumphosts...)

my $basepth = "/usr/local/etc/hookem-banem/";

my $debuglog = "/var/log/hookem-banem.log";
my $statlog = "/var/log/hookem-banem.info";

my %cfg;
sub reloadconfig {
	$filtercfg = {};
	$ipfindcfg = {};
	%cfg = {};

	my $dh;
	# Read the filters first
	opendir($dh, $basepth . "filter.d") || die("Can't read files in " . $basepth . "filter.d" . ": $!");
	while (readdir($dh)) {
		next if(! -f $basepth . "filter.d/" . $_);
		next if(! /.conf$/);

		printf(DEBUGOUT " >> Rading filter config %s\n", $_) if(defined $debug && $debug > 3);
		read_filter_config($basepth . "filter.d/" . $_);
	}
	closedir $dh;


	# And services
	opendir($dh, $basepth . "service.d") || die("Can't read files in " . $basepth . "service.d" . ": $!");
	while (readdir($dh)) {
		next if(! -f $basepth . "service.d/" . $_);
		next if(! /.conf$/);

		printf(DEBUGOUT " >> Reading service config %s\n", $_) if(defined $debug && $debug > 3);
		read_service_config($basepth . "service.d/" . $_);
	}
	closedir $dh;
}

#
# Configuration ends
#

# Dont buffer the output
$| = 1 if(defined $debug);
if(defined $debug) {
	open(DEBUGOUT, ">>", $debuglog);
	$old_fh = select(DEBUGOUT);		# Flush the output as we write it
	$| = 1;
	select($old_fh);
	printf(DEBUGOUT $0 . " starting\n");
}

reloadconfig();


# Global/Tracking or Config modification vars
my %blocks;
my %whereami;
my %lastseen;
my %attempts;
my $thistime = 0;
my $lastloggedtime;
my $inline;
my $progname = "hookem-banem-server";
my $fullmessage = "";
my @forkpids;
my $havebigsubnetscounter = 300;				# Initailly this is high as we dont call it often, sig_alarm will set it down later
my $logsprocessed = 0;
$warmtime += time() if($warmtime > 0);

# Older servers may not know what port number we are refering to, so to make sure its universal we convert them to numeric here
# @todo Should we do the same with protocol, I have not seen a server that does not know what udp or tcp are, but how universal do we want to be?
foreach $service(keys %cfg) {
	next if(!$cfg{$service}{"enabled"});

	my @ports = split(/,/, $cfg{$service}{"ports"});
	$cfg{$service}{"ports"} = "";
	foreach(@ports) {
		my $port = getservbyname($_, $cfg{$service}{"protocol"});
		$port = $_ if(!$port);

		$cfg{$service}{"ports"} .= $port . ",";
	}
	$cfg{$service}{"ports"} = substr($cfg{$service}{"ports"}, 0, -1);			# Strip the trailing comma
}


#use sigtrap 'handler', \&sig_closedown, 'normal-signals';
$SIG{"HUP"} = \&sig_status;
$SIG{"CHLD"} = "IGNORE";
$SIG{"ALRM"} = \&sig_alarm_clean;

my %ignoreblocks;
foreach(@ignoreips) {
	# Should only need to ignore the first one, since we should never increment the counter when we see it
	# @TODO Should we add subnet support? That would require adding each of the ranges the ignoreips are in
	#	  or changing the code below to loop thru each ignoreblock looking at the size
	$ignoreblocks{substr(iptobinary($_), 0, -2)} = 1;
}



# Read in a filter file
#  @param $cfgfile	The config file to read
#  @param $service	The servicename
#  @param %vars		Vars to use a replacements (passed when called by self)
#  @return Nothing  (%filtercfg will be populated)
sub read_filter_config {
	my $cfgfile = shift;
	my $vars = shift;

	my $service = $cfgfile;
	$service =~ s/^.*\/([^\/]+)\.conf$/$1/;

	my $key = "";
	my $CFGF;
	my %namedfilters;

	open($CFGF, "<", $cfgfile) or die("Could not open $cfgfile for $service\n");
	while(<$CFGF>) {
		my $msg = $_;
		$msg =~ s/#.*$//;
		$msg =~ s/\s+$//;
		$msg =~ s/^\s+//;

		next if(! $msg);

		next if($msg =~ /^\s*\[(.*)\]\s*$/);

		if($msg =~ /^\s*include (.+)\s*/) {
			read_filter_config($basepth . "filter.d/" . $1, \$vars);
			next;
		}

		if($msg =~ /^\s*?(.+?)\s*=\s*(.+?)\s*$/) {
			$key = $1;
			my $val = $2;
			if($key eq "failregex") {
				push(@{ $filtercfg{$service} }, [ [ $val ] ]);
			} elsif($key =~ /^failregex_(\w+?)([0-9]*$)/) {
				if(! @{ $namedfilters{$1} }[$2]) {
					@{ $namedfilters{$1} }[$2] = [ ];
				}
				push($namedfilters{$1}[$2], $val);
			} elsif($key eq "ipregex") {
				push(@{ $ipfindcfg{$service} }, $val);
			} else {
				$vars{$key} = $val;
			}
		}
	}
	close($CFGF);

	if(%namedfilters) {
		# Add the namned filters into the general array (we dont need the names thats just for them humans)
		foreach(keys %namedfilters) {
			push(@{ $filtercfg{$service} }, $namedfilters{$_});
		}
	}

	if($filtercfg{$service}) {
		foreach $val1 (@{ $filtercfg{$service} }) {
			foreach $val2 (@{ $val1 }) {
				$val2 = replacevars($val2, \%vars);
			}
		}

		$val2 = replacevars($ipfindcfg{$service}, \%vars);
		# @TODO Should we populate $ipfindcfg{$service} with the first search item?
	}
	printf(DEBUGOUT " >> Loaded filter config %s\n", $service) if(defined $debug && $debug > 2);
}

# Read in a config file (requires filters to be loaded first)
#  @param $cfgfile	The config file to read
#  @return Nothing  (%cfg will be populated)
sub read_service_config {
	my $cfgfile = shift;
	my %vars;

	my $service = $cfgfile;
	$service =~ s/^.*\/([^\/]+)\.conf$/$1/;

	my $key = "";
	my $CFGF;

	open($CFGF, "<", $cfgfile) or die("Could not open $cfgfile ($service)\n");
	while(<$CFGF>) {
		my $msg = $_;
		$msg =~ s/#.*$//;
		$msg =~ s/\s+$//;
		$msg =~ s/^\s+//;

		next if(! $msg);
		next if($msg =~ /^\s*\[(.*)\]\s*$/);

		if($msg =~ /^\s*?(.+?)\s*=\s*(.+?)\s*$/) {
			$key = $1;
			my $val = $2;

			# Directly setup the filters here, note we allow comma seperation as well
			if($key eq "filters") {
				if(! $filtercfg{$val}) {
					printf(DEBUGOUT " >>! Could not find filters rules named '%s', %s may not work\n", $val, $service) if(defined $debug && $debug > 1);
				} else {
					$vars{$key} = $filtercfg{$val};
				}
			} elsif($key eq "ipdetection") {
				if(! $ipfindcfg{$val}) {
					printf(DEBUGOUT " >>! Could not find ipdetection rules named '%s', %s may not work\n", $val, $service) if(defined $debug && $debug > 1);
				} else {
					$vars{$key} = $ipfindcfg{$val} 
				}
			} elsif($key eq "block_expire" || 
				$key eq "timeout" ||
				$key eq "longblock_expire" ||
				$key eq "longblock_timeout"
				) {
				$val = $1 if($val =~ /^(.*)s$/);
				$val = $1 * 60 if($val =~ /^(.*)m$/);
				$val = $1 * 3600 if($val =~ /^(.*)h$/);
				$val = $1 * 86400 if($val =~ /^(.*)d$/);
				$vars{$key} = $val;
			} else {
				$vars{$key} = $val;
			}
		}
	}
	close($CFGF);

	if($vars{"enabled"}) {
		$cfg{$service} = \%vars;
		printf(DEBUGOUT " >> Loaded service config %s\n", $service) if(defined $debug && $debug > 1);
	}
}


# Updates the process detail to indicate whats currently going on
{
my $nexttype = 0;
my $typec = 0;
sub statusupdate {
	if($warmtime > 0) {
		$0 = sprintf("%s - Warming logs - %is", $progname, $warmtime - time());
		return;
	}

	my $type;
	if($typec == 0) {
		$type = "all";
	} else {
		$type = (keys %blocks)[$typec - 1];
	}
	if(time() > $nexttype) {
		$typec++;
		$typec = 0 if($typec > scalar(keys %blocks));
		$nexttype = time() + 2;
	}

	my $watching = 0;
	my $activeblocks = 0;
	my $awatch = 0;
	my $extra = "";
	if($type eq "all") {
		if(%blocks) {
			foreach $service(keys %blocks) {
				$watching += scalar(keys $blocks{$service});
				$activeblocks += scalar(grep {$blocks{$service}{$_}{"blocked"}} keys $blocks{$service});
			}
		}
		if(%attempts) {
			$awatch += scalar(keys %attempts);
		}
	} else {
		if($blocks{$type}) {
			$watching += scalar(keys $blocks{$type});
			$activeblocks += scalar(grep {$blocks{$type}{$_}{"blocked"}} keys $blocks{$type});
		}
		if(%attempts) {
			foreach (keys %attempts) {
				$awatch++ if(substr($_, -length($type) - 1) eq "-" . $type);
			}
		}
	}
	$extra = sprintf("- %is behind (%i l/m)", time() - $thistime, $logsprocessed * 2) if(time() - $thistime > 0);

	$0 = sprintf("%s [ %s: %i blocked, %i watching, %i recent ]%s", $progname, $type, $activeblocks, $awatch, $watching - $activeblocks, $extra);
}
}

# Given an array of strings replace the vars with their real value 
sub replacevars {
	my ($input, $vars) = @_;
	return if(ref($input) ne 'ARRAY');

	# Make sure all the vars have been replaced inside the other vars before we do the main string
	#   otherwise we could end up with a replacement not being done as it replied on another one
	my $changed = 0;
	do {
		$changed = 0;
		foreach my $var1 (keys \%vars) {
			foreach my $var (keys \%vars) {
				if($vars{$var1} =~ /\%\($var\)s/) {
					$repl = $vars{$var};
					$vars{$var1} =~ s/\%\($var\)s/$repl/g;
					$changed++;
				}
			}
		}
	} while($changed > 0);

	foreach $val (@{ $input }) {
		my $repl;
		if(%vars) {
			foreach my $var (keys \%vars) {
				$repl = $vars{$var};
				$val =~ s/\%\($var\)s/$repl/g;
			}
		}

		# Fail2ban had this built in
		$repl = '(?:::f{4,6}:)?(?P<host>[\w\-.^_]+)';
		$val =~ s/<HOST>/$repl/g;
                
		# Our custom one that works with IPv6
		$repl = '(?P<host>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-hA-Z0-9:]{3,45})';
		$val =~ s/<HOST6>/$repl/g;
	}

	return $input;
}


# Returns a string reresenting the binary of the given IP
# @param $ip	The IP address to convert to binary (IPv4 and IPv6 are supported)
# @return A string representing the 1's and 0's eg. 00000010101111110101100010001100
sub iptobinary {
	my ($ip) = @_;

	if($ip =~ /:/) {			# IPv6
		return unpack("B128", inet_pton(AF_INET6, $ip));
	} else {
		return unpack("B32", inet_aton($ip));
	}
}

# Determine the next subnet to check
# @param $binary	The current binary STRING
# @return Binary string
sub _subnet_bin {
	my ($binary) = @_;
	my $bin;
	if(length($binary) > 64) {
		$bin = substr($binary, 0, 64);
	} elsif(length($binary) == 32) {
		$bin = substr($binary, 0, -$firstsubnetsize);
	} else {
		$bin = substr($binary, 0, -1);
	}

	return $bin;
}


# Work out if there is a larger subnet that is causing the issues, if there is block it and remove the individual IPs
sub havebigsubnets {
	return if($havebigsubnetscounter == 0);				# If we are under heavy attack dont keep running this CPU intensive process
	$havebigsubnetscounter--;


	# Used to have a check here to make sure that under heavy load we dont call this constantly, but have removed it
	#   since it only gets called on block. HOWEVER we may need to add some code to call this during sig_alarm if we are behind in the logs
	foreach $service (keys %blocks) {
		my %ranges;				# Number of / Ranges within a prefix that are blocked
		my %hasban;				# If there is at least 1 IP in this range which is still blocked
		my %toblock;				# Queue of blocks that need to be blocked

		# The first pass is based on what we have already
		foreach(keys $blocks{$service}) {
			# @TODO Should we have some logic here that ignores an IP that is not currently blocked
			#	  unless a collection of IPs in the range are accually blocked?

			next if($blocks{$service}{$_}{"blocked"} == 2);				# It has already been blocked by a subnet rule

			# Working in a binary representation lets us handle IPv6 easily
			my $bin = _subnet_bin($blocks{$service}{$_}{"binary"});
			next if($ignoreblocks{$bin});			# So we dont block any Ips in the ignore range

			$ranges{$bin}{$_} = $blocks{$service}{$_};

			$hasban{$bin} = 0 if(! $hasban{$bin});
			if($blocks{$service}{$_}{"blocked"} == 1 || $blocks{$service}{$_}{"warmupblock"}) {
				$hasban{$bin}++;
			}
		}

		# Pass two looks for any new ranges, sets up block records.
		# This maybe more effecient using a loop until all the %ranges have gone
		my $tmpc = 0;
		my $foundblocks = 0;
		do {
			$foundblocks = 0;
			foreach $prefix (keys %ranges) {
				next if(defined($toblock{$prefix}));										# dont do the range again
				next if(! $hasban{$prefix});										# there is nothing currently blocked (maybe in a longtimeout)

				# @TODO Not sure how to do it, but should we allow configuration of this
				my $blocksize = $firstsubnetallow;			# If we cut the last $firstsubnetsize bits, this is the amount we allow (eg. for 3 bits, 8 prefixes are returned, so set this to 4 for 50%)
				$blocksize = 2 if(length($prefix) != 32 - $firstsubnetsize); 		# We we start taking 1 bit off, we require both subnets to be blocked before blocking further
				next if(scalar(keys $ranges{$prefix}) lt $blocksize);

				my $ip;
				my $cidr = length($prefix);
				my $suffix = "";
				if(length($prefix) <= 32) {
					$suffix = ('0' x (32 - $cidr));
					$ip = inet_ntop(AF_INET, pack("B32", $prefix . $suffix));
				} else {
					$suffix = ('0' x (128 - $cidr));
					$ip = inet_ntop(AF_INET6, pack("B128", $prefix . $suffix));
				}
				my $subnetip = $ip . "/" . $cidr;

				next if(defined($blocks{$service}{$subnetip}) && $blocks{$service}{$subnetip}{"blocked"});			# We have alreay blocked this range, we dont need to do it again

				_set_blockrecord($service, $subnetip, "");
				$nextsubnetbin = _subnet_bin($blocks{$service}{$subnetip}{"binary"});
				$ranges{$nextsubnetbin}{$subnetip} = $blocks{$service}{$subnetip};			# So that we set the blocked status to 2 later on
				$hasban{$nextsubnetbin} = 1;
				$toblock{$prefix} = {"subnetip" => $subnetip, "suffix" => $suffix, "blocksize" => $blocksize, "count" => scalar(keys $ranges{$prefix})};

printf(DEBUGOUT " ------> Found block %-17s (%s%s) where %i/%i subnets\n", $subnetip, $prefix, $suffix, scalar(keys $ranges{$prefix}), $blocksize, $service) if(defined $debug && $debug > 7);

				$foundblocks = 1;
			}

			die("Too many subnets found, something may have gone wrong") if($tmpc++ > 20);
		} while($foundblocks);

		# And the last pass, blocks the newly found subnets
		foreach $prefix (keys %toblock) {
			my $subnetip = $toblock{$prefix}{"subnetip"};

			if(! $toblock{_subnet_bin($prefix)}) {				# Dont block a subnet if another one would do it anyway
$toblock{$prefix}{"suffix"} =~ s/0/./g if(defined $debug);
printf(DEBUGOUT " ----> Blocking subnet %-17s (%s%s) where %i/%i of the subnets have already been (or would be) blocked for hitting %-10s\n", $subnetip, $prefix, $toblock{$prefix}{"suffix"}, $toblock{$prefix}{"count"}, $toblock{$prefix}{"blocksize"}, $service) if(defined $debug);
				$blocks{$service}{$subnetip}{"lasttime"} = 1;	# If we dont set this to a low value, block_ip will ignore it due to a recent block (from when we ran _set_blockrecord before)
				block_ip($service, $subnetip, "");
			} else {
$toblock{$prefix}{"suffix"} =~ s/0/./g if(defined $debug);
printf(DEBUGOUT " ----> Ignoring subnet %-17s (%s%s)\n", $subnetip, $prefix, $toblock{$prefix}{"suffix"}) if(defined $debug && $debug > 2);

			}

			# Unblock the smaller blocks/IPs, and update the stats to keep longblocks working based on the worst offender
			foreach(keys $ranges{$prefix}) {
				$blocks{$service}{$subnetip}{"totalblocks"} = _maxno($ranges{$prefix}{$_}{"totalblocks"}, $blocks{$service}{$subnetip}{"totalblocks"});
				$blocks{$service}{$subnetip}{"lasttime"} = _maxno($ranges{$prefix}{$_}{"lasttime"}, $blocks{$service}{$subnetip}{"lasttime"});
				if($ranges{$prefix}{$_}{"blocked"} == 1) {
					printf(DEBUGOUT " -!!-> Removing %-15s which was hitting %-10s as it has been blocked by %s\n", $_, $service, $subnetip) if(defined $debug && $debug > 3);
					unblock_ip($service, $_, "netblock");
				}
				$blocks{$service}{$_}{"blocked"} = 2;
				$blocks{$service}{$_}{"blockingsubnet"} = $subnetip;
			}
		}
	}
}

# Returns the maximum of the two numbers (little bit easier to read than $ranges{$prefix}{$_}{"lasttime"} > $blocks{$service}{$subnetip}{"lasttime"} ? $ranges{$prefix}{$_}{"lasttime"} : $blocks{$service}{$subnetip}{"lasttime"}
sub _maxno {
	my ($a, $b) = @_;
	return $a > $b ? $a : $b;
}

# Clean up any entires which have not been seen recently
sub sig_alarm_clean {
	my $sig_name = shift;
	if($inline && $sig_name) {
		# Dont interupt an existing run, just make a flag to say come back here. Should avoid any race conditions
		$inline = 2;
		return;
	}

	my $sigtime = time();				# thistime is the time in the log, whereas we block IPs based on real time (so we assign the time to sigtime)

	if($warmtime > 0) {
		alarm(1);
		if($sigtime < $warmtime) {
			printf(DEBUGOUT "Warming logs - %is - %s\n", $warmtime - time(), $fullmessage) if(defined $debug);
			statusupdate();
			return;
		} else {
			$warmtime = 0;
print(DEBUGOUT " -!!-> Warmed up\n") if(defined $debug);
			havebigsubnets();
			return;
		}
	} else {
print(DEBUGOUT $fullmessage . "\n") if(defined $debug);
		alarm(30);
	}

	reapforks();

	# Expire any IPs that we have not seen in a while
	foreach $service(keys %lastseen) {
		my $canexpire = $thistime - $cfg{$service}{"timeout"};
		foreach(keys $lastseen{$service}) {
			if($lastseen{$service}{$_} < $canexpire) {
				delete $whereami{$_};
				delete $lastseen{$service}{$_};
				delete $attempts{$_ . "-" . $service};
printf(DEBUGOUT " -!!-> %-15s which was hitting %-10s has gone away\n", $_, $service) if(defined $debug && $debug > 2);
			}
		}
	}

	# Expire/Unblock any IPs that have been blocked for long enough
	foreach $service(keys %blocks) {
		my $doneunblock = 0;
		do {
			$doneunblock = 0;
			foreach $ip (keys $blocks{$service}) {
				if($blocks{$service}{$ip}{"blocked"} == 2) {
					# A subnet has previously blocked this IP, check that its still in effect if not mark this one as not blocked as well
					if(! $blocks{$service}{ $blocks{$service}{$ip}{"blockingsubnet"}  }{"blocked"}) {
printf(DEBUGOUT " -!!-> Marking %-15s for %-10s as unblocked as %15s is now unblocked\n", $ip, $service, $blocks{$service}{$ip}{"blockingsubnet"}) if(defined $debug && $debug > 4);
						$blocks{$service}{$ip}{"blocked"} = 0;
						$blocks{$service}{$ip}{"warmupblock"} = 0;
						$doneunblock = 1;
					}
					next;

				} elsif($blocks{$service}{$ip}{"blocked"} == 1 || $blocks{$service}{$ip}{"warmupblock"} == 1) {
					if($blocks{$service}{$ip}{"totalblocks"} > $cfg{$service}{"long_attempts"}) {
						$canexpire = $sigtime - $cfg{$service}{"longblock_expire"};
					} else {
						$canexpire = $sigtime - $cfg{$service}{"block_expire"};
					}

					if($blocks{$service}{$ip}{"lasttime"} < $canexpire) {
if(defined $debug) {
	if($ip =~ /\//) {
		printf(DEBUGOUT " -!!-> Unblocking netblock %-15s which was hitting %-10s\n", $ip, $service);
	} else {
		printf(DEBUGOUT " -!!-> Unblocking %-15s which was hitting %-10s\n", $ip, $service) if($debug > 0);
	}
}
						$blocks{$service}{$ip}{"warmupblock"} = 0;

						unblock_ip($service, $ip, "expired") if($blocks{$service}{$ip}{"blocked"});
						$doneunblock = 1;
					}

				} else {
					$canexpire = $thistime - $cfg{$service}{"longblock_timeout"};
					if($blocks{$service}{$ip}{"lasttime"} < $canexpire) {
						# thats it, they have gone away we dont need to keep watching for a long block
printf(DEBUGOUT " -!!-> No longer watching %-15s which was hitting %-10s as it was last blocked %i seconds ago which is over %i\n", $ip, $service, ($thistime - $blocks{$service}{$ip}{"lasttime"}), $cfg{$service}{"longblock_timeout"}) if(defined $debug && $debug > 0);
						delete $blocks{$service}{$ip};
					}
				}
			}
		} while($doneunblock == 1);
	}

	if($havebigsubnetscounter == 0) {
		$havebigsubnetscounter = 1;					# So that we can accually run
		havebigsubnets() 
	}
	$havebigsubnetscounter = 2;						# Maximum of 2 havebigsubnets runs between alarms
	statusupdate();
	$logsprocessed = 0;							# Its only for status so we reset it here
	show_status();
}

# What to do when we are sent a sigterm (15), basically send an unblock for all the blocked IPs
#  @note The packet we send should include that it was a shutdown, then any clients can monitor the status and remove IPs at their own leasure
sub sig_closedown {
	my $sig_name = shift;
	$progname .= " - processing SIG$sig_name";
	my $lu = 0;
	warn "\n\n\n!!! Receieved $sig_name, sending unblock requests...\n";
	syslog('authpriv|warning', "Receieved a %s", $sig_name);
printf(DEBUGOUT " -!!-> Receieved %s\n", $sig_name) if(defined $debug);

	if(%blocks) {
		foreach $service(keys %blocks) {
			sendcmd("broadcast", "servershutdown", $service, "", 0, $cfg{$service}{"protocol"}, $cfg{$service}{"ports"}, $sig_name);
		}
	}
close(DEBUGOUT) if(defined $debug);
        closelog();
	exit;
}

# If debugging is on, a HUP signal will spit out what the current block statues are
sub sig_status {
	my $sig_name = shift;
	warn "\n\n\n!!! Receieved $sig_name, writing stats...\n";
printf(DEBUGOUT " -!!-> Receieved %s\n", $sig_name) if(defined $debug);

	show_status() if(defined $debug);

	reloadconfig();
}

sub show_status {
	open(STATOUT, ">", $statlog);
	my $headstring = ('-' x 33);
	$headstring = sprintf("+-%15.15s-+-%20.20s-+-%3.3s-+-%1.1s-+-%3.3s-+-%10.10s--%5.5s--+-%32.32s-+\n", $headstring, $headstring, $headstring, $headstring, $headstring, $headstring, $headstring, $headstring);
	print(STATOUT $headstring);
	print(STATOUT sprintf("| %15.15s | %20.20s | %3.3s | %1.1s | %3.3s | %10.10s   %5.5s | %32.32s |\n", "service", "ip", "attempts", "blocked", "totalblocks", "last", "", "binary"));
	print(STATOUT $headstring);
	foreach $service(keys %blocks) {
		# I know doesnt handle IPv6 (@TODO Handle IPv6)

		foreach $ip (sort{
			# Remember we need to strip any cidrs off before passing to inet_aton
			my $a1 = $a; 
			if($a1 =~ s/^(.*)\/(.*)$//) {
				$a1 = unpack("N", inet_aton($1)) + ($2 / 100);
			} else {
				$a1 = unpack("N", inet_aton($a1)) + .32;
			}

			my $b1 = $b; 
			if($b1 =~ s/^(.*)\/(.*)$//) {
				$b1 = unpack("N", inet_aton($1)) + ($2 / 100);
			} else {
				$b1 = unpack("N", inet_aton($b1)) + .32;
			}

			$a1 <=> $b1;
		} keys $blocks{$service}) {
			my $bs = "N";
			$bs = "Y" if($blocks{$service}{$ip}{"blocked"} == 1);
			$bs = "S" if($blocks{$service}{$ip}{"blocked"} == 2);			# Blocked by subnet

			my $atmpt = 0;
			if($attempts{$ip . "-" . $service}) {
				$atmpt = $attempts{$ip . "-" . $service};
			}

			printf(STATOUT "| %15.15s | %-20.20s | %3.3i | %1.1s | %3i | %10.10s (%-5.5s) | %32.32s |\n", $service, $ip, $atmpt, $bs, $blocks{$service}{$ip}{"totalblocks"}, $blocks{$service}{$ip}{"lasttime"}, (time() - $blocks{$service}{$ip}{"lasttime"}) . "s", $blocks{$service}{$ip}{"binary"});
		}

		if(%attempts) {
			foreach (keys %attempts) {
				next if(substr($_, -length($service) - 1) ne "-" . $service);
				my $ip = substr($_, 0, -length($service) - 1);

				my $bs = "-";
				$atmpt = $attempts{$_};

				printf(STATOUT "| %15.15s | %-20.20s | %3.3i | %1.1s | %3i | %10.10s (%-5.5s) | %32.32s |\n", $service, $ip, $atmpt, $bs, 0, 0, 0, "");
			}
		}
	}

	print(STATOUT $headstring);
	close(STATOUT);
}

# Called by the children, accually does nothing
sub sig_childexit {
	exit;
}

# Check for any completed forks
sub reapforks {
	# Check for any finished forks (this may mean a processes will hang around for 60 seconds or so)
	my $closing = 0;
	do {
		$closing = waitpid(-1, WNOHANG);
		shift @forkpids;
	} while($closing > 0);
}

# Manage the number of forks that we have running at any one time
#   to avoid fork bombing
#  @return pid of the fork command when its available
#  @note This will stop execution until there is an available fork
sub nextfork {
	reapforks();
	if(scalar(@forkpids) > 5) {
		# wait for an existing fork to complete
		waitpid(-1, 0);
		shift @forkpids;
	}

	my $newpid = fork();
	if($newpid != 0) {
		push(@forkpids, $newpid);
	} else {
		$SIG{"TERM"} = \&sig_childexit;
		$SIG{"INT"} = \&sig_childexit;
		$SIG{"KILL"} = \&sig_childexit;
		$SIG{"HUP"} = \&sig_childexit;
#$DB::inhibit_exit = 0;
	}

	return $newpid;
}

# Setup the basic $block structure for an IP
sub _set_blockrecord {
	my ($service, $ip, $server) = @_;

	if(! $blocks{$service}{$ip}) {
		my $bin;
		if($ip =~ /^(.*)\/(.*)$/) {
			$bin = substr(iptobinary($1), 0, $2);
		} else {
			$bin = iptobinary($ip);
		}
		$blocks{$service}{$ip} = {
			"blocked" => 0, 				# Is the IP currently blocked, 0 = no, 1 = yes, 2 = yes by a subnet
			"totalblocks" => 0, 				# Number of times this has been blocked duirng the long period
			"firstserver" => $server, 			# Used to determine which server we blocked on the first time (so when we come to unblock we only send back to this server), if totalblocks > 1 this is ignored
			"lasttime" => time(),				# The time when the block was last blocked
			"binary" => $bin, 				# The binary representation of the IP/subnet (eg. 001001001)
			"blockingsubnet" => "", 			# If blocked is 2, this is the subnet that should be checked
			"warmupblock" => 0,				# Only set during warmup to indicate the IP would normally be blocked
		};
	}
}

# The important part, blocking 
sub block_ip {
	my ($service, $ip, $server) = @_;

	if(grep {$ip eq $_} @ignoreips) {
printf(DEBUGOUT " -!!-> %-15s on %-10s is an IGNORED IP, not blocking\n", $ip, $service) if(defined $debug);
		return;
	}

	if(defined $blocks{$service}{$ip} && time() - $blocks{$service}{$ip}{"lasttime"} <= $cooloff) {			# Allow time for logs to stabalize before we try the ban again
printf(DEBUGOUT " -!!-> %-15s on %-10s ignored due to recent ban attempt (%i ago)\n", $ip, $service, $thistime - $blocks{$service}{$ip}{"lasttime"}) if(defined $debug && $debug > 0);
		return;
	}

	_set_blockrecord($service, $ip, $server);
	
	if($warmtime > 0) {				# Dont do any banning until warmtime has been reset
		$blocks{$service}{$ip}{"warmupblock"} = 1;
printf(DEBUGOUT " -!!-> %-15s on %-10s ignored while warming up\n", $ip, $service) if(defined $debug && $debug > 2);
		return;
	}

	my $fork = nextfork();
	if(! $fork) {
		$0 = $progname . " - Banning - " . $ip . " (" . $service . ")";
		my $cmd;

		# Create the comamnd packet
		my $action = "add";
		my $type = "block";
		my $expires;
		my $syslogmsg;
		my $bmsgtime;
		if($blocks{$service}{$ip}{"totalblocks"} > $cfg{$service}{"long_attempts"}) {
			$expires = $thistime + $cfg{$service}{"longblock_expire"};
			$bmsgtime = localtime($expires);
			$syslogmsg = sprintf("Long banning %s from $service service (ports %s) for %i seconds - %s", $ip, $cfg{$service}{"ports"}, $cfg{$service}{"longblock_expire"}, $bmsgtime);
		} else {
			$expires = $thistime + $cfg{$service}{"block_expire"};
			$bmsgtime = localtime($expires);
			$syslogmsg = sprintf("Temp banning %s from $service service (ports %s) for %i seconds - %s", $ip, $cfg{$service}{"ports"}, $cfg{$service}{"block_expire"}, $bmsgtime);
		}

		syslog('authpriv|warning', $syslogmsg);
		if($cfg{$service}{"syslog"} && $cfg{$service}{"syslog"} ne "auth") {
			# If the syslog service is not for auth, create another entry for the requested service
			syslog($cfg{$service}{"syslog"} . '|warning', $syslogmsg);
		}


		if((!$doserverfirst) || ($blocks{$service}{$ip}{"totalblocks"} > 1 || ! $server)) {
			sendcmd("broadcast", $action, $service, $ip, $expires, $cfg{$service}{"protocol"}, $cfg{$service}{"ports"}, $type);
		} else {
			sendcmd($server, $action, $service, $ip, $expires, $cfg{$service}{"protocol"}, $cfg{$service}{"ports"}, $type);
		}
		exit;				# End the forked process
	}

	# If a server has not blocked the IP and we need to reissue for an already blocked IP dont increment the counters
	if(! $blocks{$service}{$ip}{"blocked"}) {
		$blocks{$service}{$ip}{"totalblocks"}++;
		$blocks{$service}{$ip}{"lasttime"} = time();
		$blocks{$service}{$ip}{"blocked"} = 1;

		havebigsubnets() if(! ($ip =~ /\//));
		statusupdate();
	}
}

# Send a command packet to the remote servers
sub sendcmd {
	my ($to, $action, $service, $ip, $expires, $protocol, $ports, $type) = @_;

	my $msgtime = time();

	my $localtest = md5_hex($msgtime . $action . $service . $ip . $expires . $protocol . $ports . $type . $checksumsalt . int($msgtime / 1200));
	$cmd = $msgtime . "|" . $action . "|" . $service . "|" . $ip . "|" . $expires . "|" . $protocol . "|" . $ports . "|" . $type . "|" . $localtest;


	# Create socket and send it out
	if($to eq "broadcast") {
		foreach my $bip (@broadcast_ips) {
#			print DEBUGOUT "sending bip for $cmd to $bip\n";
			socket(S, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!\n";
			setsockopt(S, SOL_SOCKET, SO_BROADCAST, 1) or die "Could not setup a broadcast socket for $bip: $!\n";
			defined(send(S, $cmd, 0, sockaddr_in($bport, inet_aton($bip)))) or print "could not send message to $bip: $!\n";
			close(S);
		}
	} else {
#		print DEBUGOUT "sending bip for $cmd to $to\n";
		socket(S, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!\n";
		defined(send(S, $cmd, 0, sockaddr_in($bport, inet_aton($to)))) or print "could not send message: $!\n";
		close(S);
	}
}


sub unblock_ip {
	my ($service, $ip, $reason) = @_;

#	warn "UNBLOCK $ip from $service\n";
	syslog('authpriv|warning', "Unbanning %s from $service service (%s)", $ip, $reason);
	if($cfg{$service}{"syslog"} && $cfg{$service}{"syslog"} ne "auth") {
		# If the syslog service is not for auth, create another entry for the requested service
		syslog($cfg{$service}{"syslog"} . '|warning', "Expiring ban for %s from $service service - %s", $ip, $reason);
	}

	my $fork = nextfork();
	if(! $fork) {
		$0 = $progname . " - Unbanning - " . $ip . " (" . $service . ")";

		my $action = "exp";
		if((!$doserverfirst) || ($blocks{$service}{$ip}{"totalblocks"} > 1 || !$blocks{$service}{$ip}{"firstserver"})) {
			sendcmd("broadcast", $action, $service, $ip, 0, $cfg{$service}{"protocol"}, $cfg{$service}{"ports"}, $reason);
		} else {
			sendcmd($blocks{$service}{$ip}{"firstserver"}, $action, $service, $ip, 0, $cfg{$service}{"protocol"}, $cfg{$service}{"ports"}, $reason);
		}
		exit; 		# Exit the fork
	}

	$blocks{$service}{$ip}{"blocked"} = 0;
}


#
#
# Main code
#
#

my (undef, undef, undef, $realday, $realmonth, $realyear, , ,) = localtime();
$realyear += 1900;
$realmonth += 1;

setlogsock('unix');                     # Use the socket file rather than TCP
openlog($progname, "cons,pid", "auth");
syslog('authpriv|warning', "Starting up");

print "Starting loop...\n" if(defined $debug);
print "Waiting for warmtime to pass...\n" if(defined $debug && $warmtime > 0);
alarm(1);		# Call the clean up comamnd after 1 second, it will change it to 30 seconds if warmtime has passed
# @TODO If there is no input data, the system will stall... Need to make the read non blocking
while(<STDIN>) {
#	print $_;
	$inline = 1;
	my $proc = "";
	my $server = "";
	my $lpid = "";
	my $msg = "";
	my $facility = "";
	my $priority = "";
	my $thislogtime = "";
	$logsprocessed++;

	if(/$log_format/) {
		$facility = $+{"facility"};
		$priority = $+{"facility"};
		$thislogtime = $+{"datetime"};
		$server = $+{"server"};
		$msg = $+{"message"};
	} else { 
		print DEBUGOUT "UNKNOWN FORMAT: " . $_ . "\n" if(defined $debug && $debug > 3);
		next; 
	}

	chomp;
	$fullmessage = $_;

	print DEBUGOUT $_ . "\n" if(defined $debug && $debug > 10);

	if($thislogtime && $log_dateformat) {
		if($lastloggedtime && $thislogtime eq $lastloggedtime) {
			# Rather than do all the regex work, assume that if the date is the same
			#  as the last value then it will e the same time value (should help under heavy attack)
		} elsif($thislogtime =~ /$log_dateformat/) {
			$lastloggedtime = $thislogtime;

			my ($yr, $mon, $day, $hr, $mn, $sc);
			$yr = $+{"year"} ? $+{"year"}  : $realyear;
			$mon = $+{"month"} ? $+{"month"} : $realmonth;
			$day = $+{"day"} ? $+{"day"} : $realday;
			$hr = $+{"hour"};
			$mn = $+{"minute"};
			$sc = $+{"second"};
			$mon = $log_datemonths{$mon} if(defined $log_datemonths{$mon});

			$thistime = mktime($sc, $mn, $hr, $day, $mon - 1, $yr - 1900, 0, 0, -1);
			if(! $thistime) {
				warn("Could not parse $thislogtime using $log_dateformat, using current time\n");
				$thistime = time();
			}
		} else {
			warn("Could not parse $thislogtime using $log_dateformat, using current time\n");
			$thistime = time();
		}
	} else {
		$thistime = time();
	}

	my (undef, undef, undef, $tmptoday,,,,,) = localtime($thistime);
	$today = $tmptoday if(! $today);
# H O O K: Disabled 29/02 geting mixed dates from servers?
#	if($today != $tmptoday) {	# restart every day (sortof a memory clean up) - NOTE: We dont write data, so last few lines maybe lost
#printf(DEBUGOUT "\t\t -!> Day changed from %i to %i (%s)\n", $today, $tmptoday, $fullmessage) if(defined $debug);
#		sig_closedown("endofday");
#		exit;
#	}

	foreach $service (keys %cfg) {
		next if(!$cfg{$service}{"enabled"});
		$ip = undef;

		foreach $pat (@{ $cfg{$service}{"ipdetection"} }) {
			if($msg =~ /$pat/ ) {
				$ip = $+{"host"};
				last;
			}
		}

		next if(! $ip);													# We cannot use this line for a block
		next if(! ($ip =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-hA-Z0-9:]{3,45})$/));			# We cannot do anything with this line as its not a valid IPv4 or IPv6

# @TODO If we have 'recently' (see block_ip) banned $ip we dont need to go through pattern matching since block_ip ignores it anyway
		my $id = 0;
		# Work through each of the filter patterns
		foreach $pat (@{ $cfg{$service}{"filters"} }) {
			my $where = $whereami{$ip . "-". $service . $id};
			$where = 0 if(! $where);
printf(DEBUGOUT "\t\t ---> have %-15s hitting %-10s on %-10s for id: $id, currently pos: %i\n", $ip, $service, $server, $whereami{$ip . "-" . $service . $id}) if(defined $debug && $where gt 0 && $debug > 3);

			my $pattern = @$pat[$where];
			my $nextpattern = @$pat[$where + 1];

			foreach my $check (@$pattern) {
				if($msg =~ /$check/i ) {
					$whereami{$ip . "-" . $service . $id} = $where + 1;
					$lastseen{$service}{$ip . "-" . $service . $id} = $thistime;
printf(DEBUGOUT "\t\t\t ---> detected %-15s hitting %-10s on %-10s rule $id, pos: %i last: %s\n", $ip, $service, $server, $whereami{$ip . "-" . $service . $id}, $fullmessage) if(defined $debug && $debug > 2);

					if(! $nextpattern) {
						$attempts{$ip . "-" . $service} = 0 if(! $attempts{$ip . "-" . $service});
						if(grep {$ip eq $_} @ignoreips) {
							# Ignore IPs which are on the ignore list, but pretent they would have matched, by setting the attempts to -2 (+1 below = -1 in the logs)
							$attempts{$ip . "-" . $service} = -2;
						}
						$attempts{$ip . "-" . $service}++;
if(defined $debug) {
	my $dlongcount = "";
	if(defined($blocks{$service}{$ip})) {
		$dlongcount = " +".$blocks{$service}{$ip}{"totalblocks"};
	}
	printf(DEBUGOUT "\t\t\t\t ---> %-15s hit last rule for %-10s on %-10s (%i/%i%s): %s\n", $ip, $service, $server, $attempts{$ip . "-" . $service}, $cfg{$service}{"attempts"}, $dlongcount, $fullmessage) if($debug > 2 || ($debug > 1 && ($dlongcount || $attempts{$ip . "-" . $service} > ($cfg{$service}{"attempts"} / 2))));
}
						if($attempts{$ip . "-" . $service} >= $cfg{$service}{"attempts"} ) {
							printf(DEBUGOUT "%s BLOCK %-15s! (%i/%i, last %s): %s\n", $service, $ip, $attempts{$ip . "-" . $service}, $cfg{$service}{"attempts"}, $lastseen{$service}{$ip . "-" . $service . $id}, $fullmessage) if(defined $debug && $debug > 0);
							block_ip($service, $ip, $server);

							# Reset the last seen value (if they continue on another server we will then block again)
							delete $attempts{$ip . "-" . $service};
							delete $lastseen{$service}{$ip . "-" . $service . $id};
						}

						# Reset the patern counter
						delete $whereami{$ip . "-" . $service . $id};
					}
					last;
				}
			}

			$id++;
		}
		# @TODO need to handle the reset patterns somehow
	}

	sig_alarm_clean(0) if($inline == 2);
	$inline = 0;
}

print "eof?\n";
sig_closedown("eof");
exit;
