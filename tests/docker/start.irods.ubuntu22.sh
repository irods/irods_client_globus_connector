#! /bin/bash

# If testing against locally built packages, uncomment the following line and adjust the version number in the deb files as necessary.
#apt-get update && apt-get install -y /irods_packages/irods-database-plugin-postgres_4.3.3-0~jammy_amd64.deb /irods_packages/irods-icommands_4.3.3-0~jammy_amd64.deb /irods_packages/irods-runtime_4.3.3-0~jammy_amd64.deb /irods_packages/irods-server_4.3.3-0~jammy_amd64.deb

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
service irods start

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
