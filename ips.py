import pymongo, datetime, re, json, os
from pymongo import MongoClient
from datetime import datetime

#User Editable Section
MAX_ATTEMPTS = 3
TIME_TO_BLOCK_HRS = 6
TIME_TO_BLOCK_MINUTES = 3
TIME_TO_BLOCK_SECONDS = TIME_TO_BLOCK_MINUTES * 60
#TIME_TO_BLOCK_SECONDS = TIME_TO_BLOCK_HRS * 3600

#Do not modify Below
client = MongoClient('localhost', 27017)
db = client.ssh_login_failures
entries = db.entries

secure = '/var/log/secure'

def main():

    with open(secure, "r") as f:
        for line in f.readlines():

            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
            is_ssh_log = line.find('ssh')
            is_failed_pw = line.find('Failed password for')
            now = datetime.now()

            #Insert failed pw attempt into DB
            if ip and is_ssh_log > 0 and is_failed_pw > 0:

                ip = ip[0]
                date = line[:16]
                date = formatDateString(date)
                datetime_object = datetime.strptime(date, '%b %d %Y %H:%M:%S')

                entry = dbEntry(ip, str(datetime_object)).toJSON()

                entry = json.loads(entry)

                foundEntry = entries.find(entry)

                seconds = (now - datetime_object).total_seconds()

                #Do not insert the same entry twice
                #Do not re insert past password attempts (If the last password attempt happend longer ago than the ban time, do not add )
                if foundEntry.count() == 0 and seconds < TIME_TO_BLOCK_SECONDS:
                    entries.insert_one(entry)
                    print("FAILED PW ATTEMPT: " + entry['IP'])
                    checkIP(ip)

    checkBlockedIps()


def checkIP(ip):
    failed_logins = entries.find({'IP' : ip})

    if failed_logins.count() > MAX_ATTEMPTS:
        blocked_ips = db.blocked_ips.find({'IP' : ip})
        #Do not insert the same entry twice
        if blocked_ips.count() == 0:
            entry = dbEntry(ip, str(datetime.now())).toJSON()
            entry = json.loads(entry)
            db.blocked_ips.insert_one(entry)
            print("BLOCKING IP: " + ip)
            os.system('/sbin/iptables -A INPUT -s ' + ip + ' -j DROP')


def checkBlockedIps():
    blocked_ips = db.blocked_ips.find({})

    now = datetime.now()

    for doc in blocked_ips:
        date_blocked = datetime.strptime(doc['Datetime'], '%Y-%m-%d %H:%M:%S.%f')
        ip = doc['IP']

        seconds = (now - date_blocked).total_seconds()

        #The ban  has expired, allow the IP
        if seconds > TIME_TO_BLOCK_SECONDS:
            os.system('/sbin/iptables -D INPUT -s ' + ip + ' -j DROP')
            db.blocked_ips.delete_many({'IP' : ip})
            entries.delete_many({'IP' : ip})
            print("ALLOWING IP: " + ip)


def formatDateString(datestr):
    parts = datestr.split('  ')

    if len(parts) > 1:
        parts2 = parts[1].split(' ')
        day = parts2[0]
        year = now = datetime.now().year
        if int(day) < 10:
            day = '0' + day
        datestr = parts[0] + ' ' + day + ' ' + str(year) + ' ' + parts2[1]
        return datestr
    else:
        parts = datestr.split(' ')
        year = now = datetime.now().year
        day = parts[1]
        datestr = parts[0] + ' ' + day + ' ' + str(year) + ' ' + parts[2]
        return datestr


class dbEntry:
    def __init__(self, IP, Datetime):
        self.IP = IP
        self.Datetime = Datetime

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
            sort_keys=True, indent=4)

if __name__ == '__main__':
    main()
