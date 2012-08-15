SSN Exposure
============

Detect US Social Security Numbers with Bro.

Configuration
-------------

There are some configuration options that you will likely want to pay attention to.  In particular, it's likely that you will want to configure the SsnExposure::prefixes variable unless you have a list of relevant SSNs for your organization in which case you will want to configure the SsnExposure::org_list variable.