SSN Exposure
============

Detect US Social Security Numbers with Bro.  This script only works with Bro 2.1.

Configuration
-------------

There are some configuration options that you will likely want to pay attention to.  In particular, it's likely that you will want to configure the SsnExposure::prefixes variable unless you have a list of relevant SSNs for your organization in which case you will want to configure the SsnExposure::ssn_file variable to point to a file on disk with a list of SSNs that are relevant for you.

Examples
--------

Prefix configuration
~~~~~~~~~~~~~~~~~~~~

Configure likely state prefixes in local.bro::

	redef SsnExposure::prefixes += {
		[$state="Ohio",         $low=268, $high=302],
		[$state="Pennsylvania", $low=159, $high=211],
	};

This method is more prone to false positives than the next method, but it's quick and easy to begin using after finding the relevant state prefixes from: http://www.mrfa.org/ssn.htm

SSN list configuration
~~~~~~~~~~~~~~~~~~~~~~

Configure the SSN list file in local.bro::

	redef SsnExposure::ssn_file = "/var/data/ssn-list.txt";

The file on disk should look like this::

	123456789
	123456788
	123456777
	123456666

This file will be reread everytime it changes at runtime.