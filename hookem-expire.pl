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
use Socket;
use Socket6;
#use IO::Socket::INET;
use Digest::MD5 qw(md5_hex);

my $bport = 2008;			# The UDP port the clients listen on to receieve the broadcasted requests
my $checksumsalt = "AnyOn3H3re2L!st3n";	# The salt which checksums will be made with (must be the same on each client)
my $broadcast_ip = "255.255.255.255";     # The networks broadcast IP

# Send a command packet to the remote servers
sub sendcmd {
        my ($to, $action, $service, $ip, $expires, $protocol, $ports, $type) = @_;

        my $msgtime = time();

        my $localtest = md5_hex($msgtime . $action . $service . $ip . $expires . $protocol . $ports . $type . $checksumsalt . int($msgtime / 1200));
        $cmd = $msgtime . "|" . $action . "|" . $service . "|" . $ip . "|" . $expires . "|" . $protocol . "|" . $ports . "|" . $type . "|" . $localtest;

        # Create socket and send it out
        socket(S, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!\n";
        # Enable broadcast
        if($to eq $broadcast_ip) {
                setsockopt(S, SOL_SOCKET, SO_BROADCAST, 1) or die "Could not setup a broadcast socket: $!\n";
        }
        defined(send(S, $cmd, 0, sockaddr_in($bport, inet_aton($to)))) or print "could not send message: $!\n";
        close(S);
}

sub showhelp {
	print $0 . " Service IP [server]\n\n";
	print "Sends an expire request for an IP on the given service\n";
	print "If a server is given the request will be directed to it, otherwise it will be broadcast to all servers\n";
	print "\nService MUST match the one sent from the server or the IP will not be unblocked\n";
	print "\n";
	print "\nNOTE: This only sends the request, servers will not confirm the removal\n";
	print "\n";
	exit 1;
}

showhelp() if(! $ARGV[0]);
showhelp() if(! $ARGV[1]);


$sendto = $broadcast_ip;
$sendto = $ARGV[2] if($ARGV[2]);
$service = $ARGV[0];
$ip = $ARGV[1];

sendcmd($sendto, "exp", $service, $ip, 0, "tcp", "0", "because");
print("Request sent to " . $sendto . " to expire " . $ip . " for the " . $service . " service\n");

exit;

