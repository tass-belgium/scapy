scapy
=====

To install scapy you need to do the following:

$git clone https://github.com/tass-belgium/scapy

$cd scapy

$sudo python setup.py install


This will have installed scapy. To test if it is working, do the following:

$scapy

When scapy is launched, try this to see if the correct version is installed:

$list_contrib()

This should show you:

igmpv3              : IGMPv3                                   status=loads
igmp                : IGMP/IGMPv2                              status=loads


