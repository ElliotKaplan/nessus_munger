# nessus_munger
Routines for connecting to a Nessus server and parsing the output. 

The operating idea is that it is better to run many small Nessus
scans, because it is always possible event that something goes wrong
with a given scan. Rather than restarting a single scan over an entire
network, split up scans makes it possible to restart from the middle
of an engagement. (I do realize that there may be functionality that
I'm unaware of for such a restart).

That said, it is more difficult for a person to parse out a large
number of individual scans through the web application than it is to
parse a single scan. Thus the idea of a command line tool for running
through multiple scans presents itself. 

This is intended to be used along side the web application so that you
can easily look through multiple scans for the same findings, and
collate the ips/ports. Specifically this is supposed to be a tool for
reporting, so that it is easy to extract information from the nessus
report and munge it into something copy-pasteable. (For example, a
list of hosts and ports vulnerable to some finding, CVEs associated
with a given plugin)





