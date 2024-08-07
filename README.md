// Copyright Marina Oprea 313CA 2022-2023

<h4> Overview </h4>
<p>
    Current source implements a simple antivirus for detecting malicious urls
or malicious traffic.
</p>

<h4> First task </h4>
<p>
    The first task checks for urls found in a given database that contains urls
with malicious behaviour. The database is dinamically allocated for ease of
giving it as function parameter. Implemented search is linear, could be
optimized for faster results (by sorting and binary search).
</p>
<p>
    Other euristics are too many digits in domain name and accessing an
executable file. These euristics are solved by investigating domain name and
url suffix.
</p>
<p>
    Added euristics base on misuse of subdomain "www." or suspicious tlds, such
as ".ru", etc. Euristics could be further investigated by loading a tlds
database for either suspicious tlds or most common and trustworthy tlds.
</p>
<p>
    Current solution proposes "OR" logical operation between euristics, either
of them being true leading to considering the url malicious.
</p>

<h4> Second Task</h4>
<p>
    Second task investigates traffic data, searching for prolonged flow duration
with prolonged average paket loading duration.
</p>
<p>
    Solution proposes identifying the positions of these data in the traffic
information. Then we investigate the numbers. Note that we base on a standard
format (0 days 00:00:00.123).
</p>

<p>
    We make sure that resources are deallocated and files are closed after
every task.
</p>
