# UStun

This is a user-space IPv6 tunnel with ip6tables-compatible user-space firewall that runs on OpenVZ/Virtuozzo guests.
The project is a continuation of Luca Bertoncello's ustun (http://www.lucabert.de/ipv6/?lang=en) with some
improvements including:

* Ability to run and control multiple tunnel instances on a single host
* Stateful firewall shared across all running tunnels, aiming to be fully compatible with ip6tables (WIP)

Config files allowing to run stateful ufw-based firewall on OpenVZ/Virtuozzo guests are in ufw folder, together with
a script emulating ip6tables-restore functionality.

To use the tunnel and firewall (with UFW on Ubuntu):
* make 
* copy ustun, usctrl, us6tables and ufw/us6tables-restore to /usr/local/sbin
* relink /sbin/ip6tables to /usr/local/sbin/us6tables
* relink /sbin/ip6tables-restore to /usr/local/sbin/us6tables-restore
* relink /sbin/ip6tables-save to /bin/true - WARNING - this will disable ip6tables-save as ufw does not require it
* backup after6.rules and before6.rules in /etc/ufw
* copy after6.rules and before6.rules to /etc/ufw

NOTE: Some of the rules have slightly different syntax. See /usr/local/sbin/us6tables-restore for info on how ip6tables
rules are rewritten. 

To create tunnel interface add the following to /etc/network/interfaces:

iface NAME_CHANGEME inet6 static
    address    IPv6_ADDR_CHANGEME
    netmask    NETMASK_CHANGEME
    pre-up     /usr/local/sbin/ustun -n NAME_CHANGEME -r REMOTE_END -l LOCAL_END -m tunnelbroker -p /run/ustun-NAME_CHANGEME.pid
    post-up    /sbin/ip -6 addr add MORE_IPs_CHANGEME dev NAME_CHANGEME
    pre-down   /sbin/ip -6 addr del MORE_IPs_CHANGEME dev NAME_CHANGEME
    post-up    /sbin/ip -6 route add ::/0 dev NAME_CHANGEME
    post-down  /bin/kill `cat /run/ustun-NAME_CHANGEME.pid` > /dev/null 2>&1 || /bin/true
    mtu        1480

WARNING:
    Most OpenVZ/Virtuozzo hosts overwrite /etc/network/interfaces upon reboot.
    It's best to put your tunnel interface into /etc/network/interfaces.ipv6 and add the following to /etc/rc.local:

    cat /etc/network/interfaces.ipv6 >> /etc/network/interfaces
    ifup NAME_CHANGEME

NOTE:
    You can have multiple tunnels running. They will share the firewall rules, but can be controlled via usctrl separately. 

To get info about your tunnel, use:

    usctrl -p `cat /run/ustun-NAME_CHANGEME.pid` -i

Providing PID (option -p or --pid) to usctrl is mandatory!