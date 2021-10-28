# Cobalt Strike Checksum evaluator for Splunk

This project leverages the Cobalt Strike checksum project from Didier Stevens: <https://github.com/DidierStevens/Beta/blob/master/metatool.py>

The python script is converted into two different python files for each calculation type and the input and output is formatted to the CSV expectation of Splunk.

`url8-checker.py` operates the URL8 calculation on URLs and `urluuid-checker.py` operates the URLUUID calculation on the URLs.

**Expected**: each script excepts the URL to be passed to as a field named `combined_uri` within Splunk.

The python scripts are added to Splunk as an external lookup.

`url8-checker.py`: expects - `combined_uri` - returns - `parsedcheck`

`urluuid-checker.py`: expects - `combined_uri` - returns - `puid`, `platform`, `architecture`, `timestamp`

---

## Define the External Lookups in Splunk ##

The python scripts should be added to Splunk as external lookups. This can be accomplished by added the following code to `transforms.conf` within an application or globally.

```conf
[cscheck]
allow_caching = 0
case_sensitive_match = 1
external_cmd = url8_check.py combined_uri
fields_list = combined_uri, parsedcheck

[urluuid]
allow_caching = 0
case_sensitive_match = 1
external_cmd = urluuid_check.py combined_uri
fields_list = combined_uri, puid, platform, architecture, timestamp
```
