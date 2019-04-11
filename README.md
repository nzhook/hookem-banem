# Hookem-banem
Monitors logs on a centralised server and distributes the block requests accross multiple servers

Supports:
 - IPv6 
 - Subnet blocking

Original inspiration taken from Fail2ban https://www.fail2ban.org (but written in perl)


## Server Setup
- Enable services to monitor by changing settings in the monitor.d directory (see monitor.d/EXAMPLE.conf for setting descriptions)
- You can add additional rulesets in the filter.d directory (see filter.d/EXAMPLE.conf for how these work)
- Optional: Change @broadcast_ips, @ignoreips, $bport and $checksumsalt in hookem-server.pl to customise your environment
- Send the centalised logs to stdin of hookem-server.pl, example for syslog-ng:
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
This is the harder part of the setup as each server/client could be different depending on your environment

- Copy hookem-client.pl to the server/client 
- **Modify the $myparent line to match the IP hookem-server sends from**
- Optional: If you changed $bport and/or $checksumsalt you need to make the same change to each client
- Optional: Modify the commands needed to add the blocks for this server (default uses iptables)
- Set it to start on boot using your normal method (systemd, sysvinit...)
- Start the client and you should see it start to block requests as hookem-server detects and sends them


**NOTE** hookem-server will only know about activity sent to the server it is monitoring, so each server running the client should send syslog messages to the master. You can normally do this by adding the following line to the syslog.conf (or rsyslog.conf):
```
*.* @your.syslog-server
```
(one @ uses UDP which is normally fine)
