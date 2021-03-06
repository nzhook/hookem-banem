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
use IO::Socket;
use Digest::MD5 qw(md5_hex);

use strict;

use Data::Dumper;

# Hookem-Banem client side tool which listens and blocks the incomming IPs
#
# nzHook - September 2013
#
# @TODO:
#   - look at what is currently in the table and try and load it (in case we crashed and left entries around)

# You can define some local ignores here
#  Or just trust the servers list
my @ignoreips;

# Should we fork into the backgroud
# @todo Should make this an argument
my $runasdaemon = 1;

# Should processing errors be sent to syslog or just ignored
my $errorstosyslog = 1;

# The name to show in syslog (not used if errorstosyslog is not enabled)
my $syslogname = "hookem-client";

# The longest any IP will be blocked for (if the server does not send an unblock request, we will unblock it after this amount of time)
my $maxexpire = 3600 * 2;

# The port to listen on
my $bport = 2008;

# The PID file to indicate we are running (remember if you use $setuid you need to have write access to the directory to delete the file on close)
my $pidfile = "/tmp/hookem-client.pid";

# The IP that can talk to us, we ignore anything else (@todo should this be an array?)
my $myparent = "210.48.108.14";

# The salt which checksums will be made with (must be the same on the server listed as $myparent)
my $checksumsalt = "AnyOn3H3re2L!st3n";

# If a cache_block is defined, how often to refresh the cache (seconds)
my $cacherefresh = 600;

# The commands to execute:
my %commands = {};

if(1) {
	# The basic command prefix (eg. sudo iptables)
	#   This is here to make the %commands easier, its not used anywhere else
#	my $base4cmd = "sudo /sbin/iptables";
	my $base4cmd = "/sbin/iptables";
	my $base6cmd = "/sbin/ip6tables";

	# The commands to execute:
	my %commands4 = (
		"new_service" 	=> $base4cmd . ' -N hookem-INP<service>; ' . $base4cmd . ' -I INPUT 1 -m state --state NEW -p <protocol> -m multiport --dports <port> -j hookem-INP<service>',
		"check_service"	=> $base4cmd . ' -nL INPUT | grep -qi "hookem-INP<service>.*state NEW multiport dports <port>"',				# Note: We do an -n here, so we expect the ports to come in as their numeric form. (we dint check this everytime, so there is no cache version)
		"end_service" 	=> $base4cmd . ' -D INPUT -m state --state NEW -p <protocol> -m multiport --dports <port> -j hookem-INP<service> && ' . $base4cmd . ' -X hookem-INP<service>',

		"new_block" 	=> $base4cmd . ' -I hookem-INP<service> 1 -j DROP -s <ip>',
#		"check_block" 	=> $base4cmd . ' -nL hookem-INP<service> | grep -q "<ip>"',
		"check_block" 	=> undef,
		"cache_block" 	=> $base4cmd . ' -nL hookem-INP<service>',					# Remember should return everything for that block, only refreshes every $cacherefresh seconds
		"grep_block" 	=> '<ip>',
		"end_block" 	=> $base4cmd . ' -D hookem-INP<service> -j DROP -s <ip>',
		"mass_unblock"	=> $base4cmd . ' -F hookem-INP<service>',
	);
	$commands{4} = \%commands4;

	my %commands6 = (
		"new_service" 	=> $base6cmd . ' -N hookem-INP<service>; ' . $base6cmd . ' -I INPUT 1 -m state --state NEW -p <protocol> -m multiport --dports <port> -j hookem-INP<service>',
		"check_service"	=> $base6cmd . ' -nL INPUT | grep -qi "hookem-INP<service>.*state NEW multiport dports <port>"',				# Note: We do an -n here, so we expect the ports to come in as their numeric form. (we dint check this everytime, so there is no cache version)
		"end_service" 	=> $base6cmd . ' -D INPUT -m state --state NEW -p <protocol> -m multiport --dports <port> -j hookem-INP<service> && ' . $base6cmd . ' -X hookem-INP<service>',

		"new_block" 	=> $base6cmd . ' -I hookem-INP<service> 1 -j DROP -s <ip>',
#		"check_block" 	=> $base6cmd . ' -nL hookem-INP<service> | grep -q "<ip>"',
		"check_block" 	=> undef,
		"cache_block" 	=> $base6cmd . ' -nL hookem-INP<service>',					# Remember should return everything for that block, only refreshes every $cacherefresh seconds
		"grep_block" 	=> '<ip>',
		"end_block" 	=> $base6cmd . ' -D hookem-INP<service> -j DROP -s <ip>',
		"mass_unblock"	=> $base6cmd . ' -F hookem-INP<service>',
	);
	$commands{6} = \%commands6;
} else {
	$commands{4} = (
		"new_service" 	=> undef,
		"check_service"=> undef,
		"end_service" 	=> undef,

		"new_block" 	=> 'sudo /sbin/route add -host <ip> reject',
		"check_block" 	=> 'sudo /sbin/route -n | grep -q "<ip>"',
		"end_block" 	=> 'sudo /sbin/route del -host <ip> reject',
		"mass_unblock"	=> undef,
	);
}

# If syslog is not in use we dont need to load it
if($errorstosyslog) {
	use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock

	setlogsock('unix');                     # Use the socket file rather than TCP
	openlog($syslogname, "cons,pid", "auth");
}


# If you are using sudo, run as this user
my $setuid = "root";

#
# Configuration ends
#

# Global/Tracking vars
my $nextcheck = 0;			# Will force a clean up run straight away, but we then dont have to calculate it once we have the first timestamp
my %blocks;
my %services;
my %cache;

use sigtrap 'handler', \&sig_closedown, 'normal-signals';
#$SIG{"HUP"} = \&sig_status;

# Clean up any entires which have not been seen recently
sub clean_old {
	# Expire/Unblock any IPs that have been blocked for long enough
	my $canexpire = time() - $maxexpire;
	foreach my $service(keys %blocks) {
		foreach my $ip (keys %{ $blocks{$service} }) {
			if($blocks{$service}{$ip}{"lasttime"} < $canexpire || time() > $blocks{$service}{$ip}{"expires"}) {
				unblock_ip($service, $ip, "forceexpire");
			}
		}
	}

	$nextcheck = time() + 300;		# It should be rare that we need to clean expired IPs as the server should tell us
}

# What to do when we are sent a sigterm (15)
#   If a quickunblock exists run it, otherwise we have to unblock all the IPs we have listed
sub sig_closedown {
	my $sig_name = shift;
	$0 .= " - processing SIG$sig_name";
        syslog('auth|warning', "Receieved a $sig_name, sending unblock requests", $sig_name) if($errorstosyslog);
	warn "\n\n\n!!! Receieved $sig_name, sending unblock requests...\n";

	close(SOCKET);

	if(%blocks) {
		foreach my $service(keys %blocks) {
			my %vars = (
				"service" => $service,
				"protocol" => $services{$service}{"protocol"},
				"port" => $services{$service}{"port"},
			);

			# TODO Need to handle this more dynamically
			godo("mass_unblock", 6, 0, %vars);
			if(godo("mass_unblock", 4, 0, %vars)) {
				delete @blocks{$service};				# Should all be gone now
			} else {
				warn "Unblocking IPs for $service\n";
				foreach my $ip (keys %{ $blocks{$service} }) {
					unblock_ip($service, $ip, "localshutdown");
					delete $blocks{$service}{$ip};			# Be nice to memory
				}
			}

			# TODO Need to handle this more dynamically
			godo("end_service", 6, 0, %vars);
			godo("end_service", 4, 0, %vars);
		}
	}
        unlink($pidfile) or die("Could not delete $pidfile: $!");

	exit;
}

# A HUP signal will spit out what the current block statues are
sub sig_status {
	my $sig_name = shift;
	warn "\n\n\n!!! Receieved $sig_name, writing stats...\n";

	my $headstring = ('-' x 33);
	$headstring = sprintf("+-%15.15s-+-%20.20s-+-%10.10s-+\n", $headstring, $headstring, $headstring);
	print $headstring;
	foreach my $service(keys %blocks) {
		foreach my $ip (keys %{ $blocks{$service} }) {
			printf("| %15.15s | %-20.20s | %10.10s |\n", $service, $ip, time() - $blocks{$service}{$ip}{"lasttime"});
		}
	}
	print $headstring;
}

# Go do a command, replacing the tokens in the command beforehand
# @param $ipv	The IP version to use (eg. 4 or 6)
# @param $cmd	The command name to run
# @param $default If the command is not defined return this value
# @param %vars	The vars to do token replacement with
# @return The return code of the executed code (or $default if command is not defined)
sub godo {
	my $cmd = shift;
	my $ipv = shift;
	my $default = shift;
	my %vars = @_;

	my $resp = 0;
	return $default if(! $commands{$ipv}{$cmd});

	$cmd = $commands{$ipv}{$cmd};

	my ($k, $v);
	foreach $k (keys %{ \%vars }) {
		$v = $vars{$k};
		$cmd =~ s/<$k>/$v/g;
	}

	warn $cmd . "\n" if(! $runasdaemon);
	$resp = system($cmd);
	$resp = $? >> 8;
	warn("\t returned $resp\n") if(! $runasdaemon);
	return $resp;
}

# Load the current rulesets into memory
#  called after adding a block as well as  when checking a block if $cacherefresh has passed
# @param %vars 	Vars to pass into the godo comand, we use the the IP and service
sub cache_blocked {
	my %vars = @_;

	$cache{$vars{"service"}}{"block"} = "";

	# TODO: This needs to be more dynamic. For now we do two runs one for ipv4 and one for ipv6
	if($commands{4}{"cache_block"}) {
		my $cmd = $commands{"cache_block"};
		my ($k, $v);
		foreach $k (keys %{ \%vars }) {
			$v = $vars{$k};
			$cmd =~ s/<$k>/$v/g;
		}

		warn $cmd . "\n" if(! $runasdaemon);
		open(CMDPIPE, "-|", $cmd) or return 0;
		while(<CMDPIPE>) {
			$cache{$vars{"service"}}{"block"} .= $_;
		}
		close(CMDPIPE);
	}

	if($commands{6}{"cache_block"}) {
		my $cmd = $commands{6}{"cache_block"};
		my ($k, $v);
		foreach $k (keys %{ \%vars }) {
			$v = $vars{$k};
			$cmd =~ s/<$k>/$v/g;
		}
	
		$cache{$vars{"service"}}{"block"} = "";
		warn $cmd . "\n" if(! $runasdaemon);
		open(CMDPIPE, "-|", $cmd) or return 0;
		while(<CMDPIPE>) {
			$cache{$vars{"service"}}{"block"} .= $_;
		}
		close(CMDPIPE);
	}

	$cache{$vars{"service"}}{"lastblocktime"} = time();
}


# Check to see if the IP is currently blocked, this is done as a sub
#  so that we dont have to call the shell command everytime we see a new request
#  to do this we store the command output and only regrab it once every minute
#  this still allows for the rules to be manually flushed without us constantly
#  checking
# @param %vars 	Vars to pass into the godo comand, we use the the IP and service
# @return 1 if blocked, 0 is not
sub is_blocked {
	my %vars = @_;

	if($commands{"cache_block"} && $commands{"grep_block"}) {
		if(! defined($cache{$vars{"service"}}{"block"}) || time() - $cache{$vars{"service"}}{"lastblocktime"} >= $cacherefresh) {
			cache_blocked(%vars);
		}

		my $cmd = $commands{"grep_block"};
		my ($k, $v);
		foreach $k (keys %{ \%vars }) {
			$v = $vars{$k};
			$cmd =~ s/<$k>/$v/g;
		}

		if($cache{$vars{"service"}}{"block"} =~ /$cmd/m) {
			return 1;
		}

		return 0;		# If cache is defined and we get here then assume its not blocked
	}

	return 0 if(! $commands{"check_block"});

	if(godo("check_block", $vars{"ipv"}, 1, %vars)) {
		return 1;
	}
	return 0;
}


# Check if the main INPUT chain has our rule (and its still correct)
# @param %vars	Vars to pass into the godo comand
# @return 1 if the service exists, 0 if it did not (or failed to be created)
sub service_check {
	my %vars = @_;
	my ($cmd, $resp);

	if(defined($services{$vars{"ipv"} . "-" . $vars{"service"}})) {
		return $services{$vars{"ipv"} . "-" . $vars{"service"}}{"active"} if($vars{"port"} eq $services{$vars{"ipv"} . "-" . $vars{"service"}}{"port"} && time() - $services{$vars{"ipv"} . "-" . $vars{"service"}}{"lastcheck"} < $cacherefresh);		# We dont need to check the service exists on every run

		# Detect a change to the port numbers and remove the old rule if they differ
		#   This does mean there might be a few moments when an attacker could get in
		#   but its easier to do here than to rewrite the below
		if($vars{"port"} ne $services{$vars{"ipv"} . "-" . $vars{"service"}}{"port"}) {
			godo("end_service", $vars{"ipv"}, 0, $services{$vars{"ipv"} . "-" . $vars{"service"}});
		}
	}

	$services{$vars{"ipv"} . "-" . $vars{"service"}} = {
		"protocol" => $vars{"protocol"},
		"port" => $vars{"port"},
		"lastcheck" => time(),
		"active" => 0,
	};

	if(godo("check_service", $vars{"ipv"}, 1, %vars)) {
		warn("Creating new " . $vars{"service"} . " rule\n");
		return 0 if(godo("new_service", $vars{"ipv"}, 0, %vars));			# If no comamnd exists we assume we can contiune
	}

	$services{$vars{"ipv"} . "-" . $vars{"service"}}{"active"} = 1;
	return 1;
}


# The important part, blocking 
sub block_ip {
	my ($service, $ip, $expires, $protocol, $ports, $type) = @_;

	if(grep {$ip eq $_} @ignoreips) {
		warn "$ip for $service is an IGNORED IP, not blocking\n";
		return;
	}

	# We track this even if the service fails to add, that way we wont constantly be trying to create the service
	$blocks{$service}{$ip} = {"ports" => $ports, "protocol" => $protocol, "type" => $type, "lasttime" => time(), "expires" => $expires };

	my $ipv;
	if($ip =~ /:/) {
		$ipv = 6;
	} else {
		$ipv = 4;
	}
	
	my %vars = (
		"ip" => $ip,
		"ipv" => $ipv,
		"protocol" => $protocol,
		"port" => $ports,
		"service" => $service,
	);


	# Check that the service exists
	return 0 if(! service_check(%vars));				# If the service commands fail, then we wont be able to add the rules


	# Check if the IP is already blocked
	return 0 if(is_blocked(%vars));			# Already exists we dont need to continue

	# Insert the IP into the chain
	godo("new_block", $ipv, 0, %vars);
	cache_blocked(%vars);				# Recache since the output will now have changed
}

sub unblock_ip {
	my ($service, $ip, $reason) = @_;

	return if(! $blocks{$service}{$ip});				# If we dont have data on it, we cant unblock it

	my $ports = $blocks{$service}{$ip}{"ports"};
	my $protocol = $blocks{$service}{$ip}{"protocol"};

	my $ipv;
	if($ip =~ /:/) {
		$ipv = 6;
	} else {
		$ipv = 4;
	}

	my %vars = (
		"ip" => $ip,
		"ipv" => $ipv,
		"protocol" => $blocks{$service}{$ip}{"protocol"},
		"port" => $blocks{$service}{$ip}{"ports"},
		"service" => $service,
	);

	# Check if the IP is blocked
	return 0 if(godo("check_block", $ipv, 0, %vars));			# Does not exist we dont need to continue

	# Remove the rule from the chain
	#  @TODO In case of duplicates should we remove any duplicates as well or do we assume block wont have done that?
	godo("end_block", $ipv, 0, %vars);

	# @TODO Should we remove the chain from input when there are no more items to process? It would keep it cleaner

	delete $blocks{$service}{$ip};
}


#
#
# Main code
#
#

# Dont buffer the output
$| = 1;
$0 = "hookem-client";

if(-f $pidfile) {
	open(PIDSTATE, "<$pidfile") or die("Could not open state file ($pidfile)");
	my $state = kill 0, <PIDSTATE>;
	close(PIDSTATE);
	die("Already running (Check $pidfile)\n") if($state);
}

if($runasdaemon) {
	exit if(fork());
}

open(PIDSTATE, ">$pidfile") or die("Could not create state file ($pidfile)");
print PIDSTATE "$$";
close(PIDSTATE);


if($setuid != "root") {
	my $myuid = getpwnam($setuid) or die "Cannot identify uid for $setuid";
	if($> != $myuid) {
		chown($myuid, 0, $pidfile);			# So we can delete it later
		$> = $myuid;
		die("Could not change user to $setuid ($myuid)") if($> != $myuid);
		$< = $>;
	}
}

my $protocol = getprotobyname('udp');
socket(SERVER, PF_INET, SOCK_DGRAM, $protocol) 			or die "cant create socket: $!";
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) 	or die "setsockopt: $!";
bind(SERVER, sockaddr_in($bport, INADDR_ANY)) 			or die "bind failed: $!";

print "Listening on UDP port: $bport\n";


chdir('/');
if($runasdaemon) {
	close(STDERR);
	close(STDOUT);
	close(STDIN);
}

# The infinite loop
while(1) {
	# Check the lastseen queues every minute
	clean_old() if(time() ge $nextcheck);

	my $inbound = "";
	my $peeraddr = recv(SERVER, $inbound, 256, 0);
	if(! defined($inbound)) {
		syslog('auth|err', "Invalid recv from " . $peeraddr . ", ignored") if($errorstosyslog);
		warn "Invalid recv from " . $peeraddr . ", ignored\n";
		next 
	}

	my($rport, $peerhost) = sockaddr_in($peeraddr);
	$peerhost = inet_ntoa($peerhost);

	warn "Incomming message from " . $peerhost . " = " . $inbound . "\n" if(! $runasdaemon);
	if($peerhost ne $myparent) {
		syslog('auth|err', "Invalid sender (" . $peerhost . "), ignored") if($errorstosyslog);
		warn "Invalid sender (" . $peerhost . "), ignored\n";
		next 
	}

	my ($msgtime, $action, $service, $ip, $expires, $protocol, $ports, $type, $checksum) = split(/\|/, $inbound);
	if(abs(time() - $msgtime) > 300) {
		syslog('auth|err', "Request from " . $peerhost . " expired by " . abs(time() - $msgtime) . " seconds, ignored") if($errorstosyslog);
		warn $inbound . "\n";
		warn "Request expired by ".abs(time() - $msgtime) ."s, ignored\n";
		next;
	}

	my $localtest = md5_hex($msgtime . $action . $service . $ip . $expires . $protocol . $ports . $type . $checksumsalt . int($msgtime / 1200));
	if($localtest ne $checksum) {
		syslog('auth|err', "Invalid checksum from " . $peerhost . ", ignored") if($errorstosyslog);
		warn $inbound . "\n";
		warn "Invalid checksum ($checksum / $localtest) in message, ignored\n";
		next;
	}

	if(! $ip || ! ($ip =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]+)?|[a-hA-Z0-9:]{3,45}(\/[0-9]+)?)$/)) {
		syslog('auth|err', "Invalid IP (" . $ip . ") from " . $peerhost . ", ignored") if($errorstosyslog);
		warn "Invalid IP ($ip) in message, ignored\n";
		next 
	}

	if($action eq "add") {
		block_ip($service, $ip, $expires, $protocol, $ports, $type);
	} elsif($action eq "exp") {
		unblock_ip($service, $ip, $type);
	} else {
		syslog('auth|err', "Unknown action (" . $action . ") from " . $peerhost . ", ignored") if($errorstosyslog);
		warn("Unknown action ($action) in message, ignored\n");
	}
}

warn "end of loop?\n";
sig_closedown();
exit;
