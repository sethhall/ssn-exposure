SSN Exposure
============

Detect US Social Security Numbers with Bro.  This script only works with Bro 2.1 and 2.2.

Installation
------------

::

	cd <prefix>/share/bro/site/
	git clone git://github.com/sethhall/ssn-exposure.git
	echo "@load ssn-exposure" >> local.bro

After the ssn-exposure module is loaded, follow the configuration examples below.  One or both of the following options must be done or the script won't do anything.

Configuration
-------------

There are some configuration options that you will likely want to pay attention to.  In particular, it's likely that you will want to configure the SsnExposure::prefixes variable unless you have a list of relevant SSNs for your organization in which case you will want to configure the SsnExposure::ssn_file variable to point to a file on disk with a list of SSNs that are relevant for you.

Examples
--------

Prefix configuration
~~~~~~~~~~~~~~~~~~~~

This method is more prone to false positives than the next method, but it's quick and easy to begin using after finding the relevant state prefixes from: http://www.mrfa.org/ssn.htm

Configure likely state prefixes in local.bro::

	redef SsnExposure::prefixes += {
		[$state="Ohio",         $low=268, $high=302],
		[$state="Pennsylvania", $low=159, $high=211],
	};

SSN list configuration
~~~~~~~~~~~~~~~~~~~~~~

A list of "known SSNs" which will be used for validation after candidate values are extracted from the network.

Configure the SSN list file in local.bro::

	redef SsnExposure::ssn_file = "/var/data/ssn-list.txt";

Create the ssn-list.txt (or whatever file you referenced above)::

	123456789
	123456788
	123456777
	123456666

This file will be reread everytime it changes at runtime so updates do not require a restart.
