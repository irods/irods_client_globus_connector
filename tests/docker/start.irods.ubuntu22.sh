#! /bin/bash

send_irods_heartbeat() {
    response=$(echo -e "\x00\x00\x00\x33<MsgHeader_PI><type>HEARTBEAT</type></MsgHeader_PI>" | netcat 127.0.0.1 1247)
}


# If testing against locally built packages, uncomment the following line and adjust the version number in the deb files as necessary.
#apt-get update && apt-get install -y /irods_packages/irods-database-plugin-postgres_5.0.2-0~jammy_amd64.deb /irods_packages/irods-icommands_5.0.2-0~jammy_amd64.deb /irods_packages/irods-runtime_5.0.2-0~jammy_amd64.deb /irods_packages/irods-server_5.0.2-0~jammy_amd64.deb

# Start the Postgres database.
service postgresql start
counter=0
until pg_isready -q
do
    sleep 1
    ((counter += 1))
done
echo Postgres took approximately $counter seconds to fully start ...

#### Set up iRODS ####
/var/lib/irods/scripts/setup_irods.py < /var/lib/irods/packaging/localhost_setup_postgres.input

#### Start iRODS ####
sudo -H -u irods -g irods bash -c "irodsServer -d"

# make sure iRODS is done starting up or the commands below will fail
send_irods_heartbeat
while [[ "$response" != "HEARTBEAT" ]]; do
    sleep 1
    send_irods_heartbeat
done


#### Create user1 in iRODS ####
sudo -H -u irods -g irods bash -c "iadmin mkuser user1 rodsuser"
sudo -H -u irods -g irods bash -c "iadmin moduser user1 password user1"

#### Create resc1 and resc2 resources in iRODS ####
sudo -H -u irods -g irods bash -c "iadmin mkresc resc1 unixfilesystem `hostname`:/tmp/resc1"
sudo -H -u irods -g irods bash -c "iadmin mkresc resc2 unixfilesystem `hostname`:/tmp/resc2"

#### Give root an environment to connect to iRODS ####
echo 'localhost
1247
rods
tempZone
rods' | iinit

mkdir -p /projects/irods/vsphere-testing/externals/

cd /

#### Keep container running ####
tail -f /dev/null
