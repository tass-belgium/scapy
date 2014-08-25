scapy
=====

This is a fork of scapy (development branch). We use it to extend the existing functionality with required features.

New features we plan to add:

* Support for IGMPv1, IGMPv2, IGMPv3
* Support to work with a single socket during a scapy session

INSTALL
=======

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


COMITTING
=========
Before committing changes to this project do the following (cleans up the branch):

$sudo python setup.py clean --all
