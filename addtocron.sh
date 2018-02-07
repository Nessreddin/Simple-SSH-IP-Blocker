
crontab -e
crontab -l | { cat; echo "*/1 * * * * /usr/bin/python /root/BCIT/COMP8006/A3/IPS_PY/ips.py"; } | crontab -
