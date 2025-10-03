#! /bin/bash

# install iRODS client packages built by development environment 
/install_local_irods_packages.sh

#### Give root an environment to connect to iRODS as rods  ####
#### Needed to set up testing.                             ####
echo 'irods
1247
rods
tempZone
rods' | iinit

#### Add user1 as a local user for testing ####
useradd user1 -m -s /usr/bin/bash

#### Give user1 an environment to connect to iRODS ####
sudo -H -u user1 bash -c "
echo 'irods
1247
user1
tempZone
user1' | iinit"

#### configure globus certs ####
# sometimes the certs are automatically created and sometimes not
if ! [ -f /etc/grid-security/certificates/*.0 ]; then
    sudo grid-ca-create -noint
fi

# this seems required to run grid-cert-request
mkdir /var/adm
touch /var/adm/wtmp
touch /var/log/messages

HEX_ID=$(ls /etc/grid-security/certificates/*.0 | cut -d/ -f5 | cut -d. -f1)
sed -i 's|= policy_match|= policy_anything|g' /etc/grid-security/certificates/globus-host-ssl.conf.${HEX_ID}
sed -i 's|cond_subjects     globus       .*|cond_subjects     globus       '"'"'"*"'"'"'|g' /etc/grid-security/certificates/${HEX_ID}.signing_policy
grid-cert-request -ca ${HEX_ID} -nopw -cn $(hostname) -force # creates ~/.globus/usercert.pem usercert_request.pem userkey.pem
cp ~/.globus/userkey.pem /etc/grid-security/hostkey.pem
cp /etc/grid-security/certificates/${HEX_ID}.0 ~/.globus/${HEX_ID}.0
cp /etc/grid-security/certificates/${HEX_ID}.signing_policy ~/.globus/${HEX_ID}.signing_policy
echo globus  | grid-ca-sign -in ~/.globus/usercert_request.pem -out hostcert.pem  # sign the cert
cp hostcert.pem /etc/grid-security/hostcert.pem
cp hostcert.pem ~/.globus/usercert.pem

#### Set up grid-mapfile ####
subject=$(openssl x509 -noout -in /etc/grid-security/hostcert.pem -subject | cut -d'=' -f2- | sed -e 's|,|/|g' | sed -e 's|/ |/|g' | sed -e 's/ = /=/g')
echo "\"/$subject\" rods" | sudo tee -a /etc/grid-security/grid-mapfile

#### Set up /etc/gridftp.conf also allowing user1 to user anonymous ftp ####
echo 'port 2811
$LD_LIBRARY_PATH "$LD_LIBRARY_PATH:/iRODS_DSI"
$irodsConnectAsAdmin "rods"
$spOption irods_client_globus_connector
$numberOfIrodsReadWriteThreads 3
$irodsParallelFileSizeThresholdBytes 33554432
$spOption irods_client_globus_connector
$irodsResourceMap "/etc/resource_mapfile"

load_dsi_module iRODS
auth_level 4

allow_anonymous 1
anonymous_names_allowed user1
anonymous_user user1
' | tee -a /etc/gridftp.conf

#### Create a resource_mapfile ####
echo '/tempZone/home/rods/dir1;resc1
/tempZone/home/rods/dir2;resc2' > /etc/resource_mapfile

### Build and install the gridftp plugin
mkdir /bld_irods_client_globus_connector
cd /bld_irods_client_globus_connector
cmake /irods_client_globus_connector
export QA_RPATHS=$(( 0x0002|0x0004 ))  # TODO(#126): cmake incorrectly reporting invalid RPATH.
make -j package
dnf -y --nogpgcheck install *.rpm
rm *.rpm

#### Start gridftp server ####
/usr/sbin/globus-gridftp-server -allow-root -log-module stdio:buffer=0 -threads 1 -aa -c /etc/gridftp.conf -pidfile /var/run/globus-gridftp-server.pid -log-level trace,info,warn,error -logfile /var/log/gridftp.log -no-detach -config-base-path / &

#### Keep container running ####
cd /tmp # run from /tmp so that test files are created there
python3 /irods_client_globus_connector/tests/run_all_tests.py

