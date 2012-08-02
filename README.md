# UStun

This is a user-space IPv6 tunnel with ip6tables-compatible user-space firewall that runs on OpenVZ/Virtuozzo guests.
The project is a continuation of Luca Bertoncello's ustun (http://www.lucabert.de/ipv6/?lang=en) with some
improvements including:

* Ability to run and control multiple tunnel instances on a single host
* Stateful firewall shared across all running tunnels, aiming to be fully compatible with ip6tables (WIP)
