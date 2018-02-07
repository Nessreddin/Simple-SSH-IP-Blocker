# Simple-IP-Blocker


The purpose of this assignment is to design, implement and test a monitor application that will detect password guessing attempts against a service and block that IP using Netfilter. 

To accomplish this we will use a number of tools: 

* Python

* Syslog

* Ssh

* Netfilter

* Mongodb 

Our application will read /var/log/secure, process failed password attempts recording them into a database. Logic will be performed on the database entries to decide when to block/unblock IPs using netfilter. 

# Design

Parsing password attempts

1. Read /var/log/secure 

2. Parse every failed SSH password attempt

3. Check how long ago the password attempt occurred. If it was longer than the ban time, ignore it

4. If the Password attempt was recent, it occurred between now and the ban time, record it into the failed attempts table in the database.

Blocking IPs

1. Read the password attempts table by IP

2. If more than the max number of attempts occurred, block that IP

3. Record the IP and time in the blocked_ips table

Unblocking IPs

1. Read the blocked ips table

2. If the time at which the IP was blocked was longer ago than the ban time, we unblock the IP removing it from failed password attempts table as well as the blocked ips table

# Setup 

dnf install python

dnf install mongodb*

dnf install syslog*

dnf install sshd

systemctl start syslog.service

systemctl start mongod.service

systemctl start sshd.service

Modify addtocron.sh to point to your python directory, and script.

./addtocron.sh

