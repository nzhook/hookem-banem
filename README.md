# Hookem-banem
Monitors logs from a centralised server and issues a block accross all connected servers

Supports:
 - IPv6 
 - Subnet blocking
 - Longer blocks for repeat attackers


Original inspiration taken from Fail2ban https://www.fail2ban.org (but written in perl)


## Server Setup
- Enable services to monitor by changing settings in the service.d directory (see service.d/EXAMPLE.conf for setting descriptions)
- You can add additional rulesets in the filter.d directory (see filter.d/EXAMPLE.conf for how these work)
- Optional: Create a file in the config.d directory to set @broadcast_ips, @ignoreips, $bport and $checksumsalt to customise your environment
- Send the centralised logs to stdin of hookem-server.pl, example for syslog-ng:
```
destination pg_hookem { 
        program("/usr/local/bin/hookem-server.pl"); 
};
log {
        source(s_all); 
        source(s_src);
        destination(pg_hookem);
};
```
- Restart syslog-ng and the server will monitor for activity and send out broadcast requests as it detects activity


## Client setup
The client is designed to run on any device that has a base install of perl, each device may have a different way of blocking
access. By default this is done with ipset and iptables, but each command can be configured. See example_config/client_* for
examples for iptables only or routing.

To install:
- Make sure the device sends logs back to the device running hookem-server, for rsyslog add this config entry:
```
*.* @The hookem-server IP
```
(keep the @ as this uses UDP)

- Copy hookem-client.pl to the server/client 
- Create a file named hookem-client.pl.d/client.conf in the same directory as hookem-client.pl and add a line for 
```
$myparent="The hookem-server IP";
```
- Optional: If you changed $bport and/or $checksumsalt on the server, add these to the file as well
- Optional: If the device needs different commands, these can also be added (or copy one of the examples)
- Set hookem-client.pl to start on boot using your normal method (systemd, sysvinit...)
- Start the client, as hookem-server detects issues hookem-client should run the block commands
