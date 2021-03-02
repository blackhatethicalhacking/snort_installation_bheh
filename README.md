# snort_installation_bheh
Installation Methods for Snort by Cisco IPS

For Full Video:

Part 1:
https://vimeo.com/517269389 

Part 2:
https://vimeo.com/360bef638e

How to transform your RPI4 into strong Firewall (IDS)
------------------------------------------------------

apt install -y gcc libpcre3-dev zlib1g-dev libluajit-5.1-dev \libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev \bison flex libdnet autoconf libtool


Installing from the source:
---------------------------

mkdir ~/snort_src && cd ~/snort_src

wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz

tar -xvzf daq-2.0.7.tar.gz
cd daq-2.0.7

autoreconf -f -i

./configure && make && sudo make install

cd ~/snort_src

wget https://www.snort.org/downloads/snort/snort-2.9.16.tar.gz

tar -xvzf snort-2.9.16.tar.gz
cd snort-2.9.16

./configure --enable-sourcefire && make && sudo make install

Configuring Snort to run in NIDS mode :
---------------------------------------

ldconfig

ln -s /usr/local/bin/snort /usr/sbin/snort

Setting up username and folder structure:
----------------------------------------

groupadd snort

useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

mkdir -p /etc/snort/rules
mkdir /var/log/snort
mkdir /usr/local/lib/snort_dynamicrules

chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules

touch /etc/snort/rules/white_list.rules
touch /etc/snort/rules/black_list.rules
touch /etc/snort/rules/local.rules

cp ~/snort_src/snort-2.9.16/etc/*.conf* /etc/snort
cp ~/snort_src/snort-2.9.16/etc/*.map /etc/snort

Option 1. Using community rules:
--------------------------------

wget https://www.snort.org/rules/community -O ~/community.tar.gz

tar -xvf ~/community.tar.gz -C ~/

cp ~/community-rules/* /etc/snort/rules

sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf

Option 2. Obtaining registered user rules:
-----------------------------------------

wget https://www.snort.org/rules/snortrules-snapshot-29160.tar.gz?oinkcode=oinkcode -O ~/registered.tar.gz

tar -xvf ~/registered.tar.gz -C /etc/snort

Configuring the network and rule sets:
-------------------------------------
With the configuration and rule files in place, edit the snort.conf to modify a few parameters. Open the configuration file in your favourite text editor, for example using nano with the command below.

nano /etc/snort/snort.conf

# Setup the network addresses you are protecting
ipvar HOME_NET server_public_IP/32

# Set up the external network addresses. Leave as "any" in most situations
ipvar EXTERNAL_NET !$HOME_NET

# Path to your rules files (this can be a relative path)
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

# Set the absolute path appropriately
var WHITE_LIST_PATH /etc/snort/rules
var BLACK_LIST_PATH /etc/snort/rules

In the same snort.conf file, scroll down to the section 6 and set the output for unified2 to log under filename of snort.log like below.

# unified2
# Recommended for most installs
output unified2: filename snort.log, limit 128

Lastly, scroll down towards the bottom of the file to find the list of included rule sets. You will need to uncomment the local.rules to allow Snort to load any custom rules.

include $RULE_PATH/local.rules


If you are using the community rules, add the line underneath to your ruleset as well, for example just below your local.rules line.

include $RULE_PATH/community.rules

Validating settings:
-------------------

snort -T -c /etc/snort/snort.conf

Testing the configuration:
--------------------------

To test if Snort is logging alerts as intended, add a custom detection rule alert on incoming ICMP connections to the local.rules file. Open your local rules in a text editor.


nano /etc/snort/rules/local.rules

alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;)

snort -A console -i wlan0 -u snort -g snort -c /etc/snort/snort.conf

snort -r /var/log/snort/snort.log.

Running Snort in the background:
--------------------------------

nano /lib/systemd/system/snort.service

[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i wlan0

[Install]
WantedBy=multi-user.target


systemctl daemon-reload

systemctl start snort

systemctl status snort



