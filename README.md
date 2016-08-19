# Nessus-Scripts
Scripts to export data scan from Nessus into .nessus file (or other extension)

## How it works

### Requirements
* Nessus 6.x
* Python

Once you put your auth details in a config file (config.conf), you can run it unattended to download all last reports.

### Commands
<code>./nessus_getter.py -c path/to/config -a</code>

(If you'd like to just get a particular report, run without -a to enter in interactive mode)
