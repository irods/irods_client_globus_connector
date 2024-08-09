Test Framework
==============

This is a test framework for testing the irods_client_globus_connector.

Running Tests
-------------

To run the tests, first make sure you have the code that is to be tested checked out.

Build the Docker images by executing the following in this directory:

```
docker-compose build
```

Then run one or more of the following to execute the test on the Globus server of your choice.

``` 
docker-compose run globus-ubuntu20
docker-compose run globus-ubuntu22
docker-compose run globus-ubuntu24
docker-compose run globus-el8
docker-compose run globus-el9
docker-compose run globus-debian11
docker-compose run globus-debian12
```
Running Tests Against Unreleased Versions of iRODS
--------------------------------------------------

To run the tests against unreleased versions of iRODS, first the iRODS packages need to be built and stored in a local directory. The [iRODS Development Environment](https://github.com/irods/irods_development_environment) can be used to build the packages for each of the OS's.

After this is done, make the changes to the following files to use these built packages:

1. Update `docker-compose.yml` and uncomment the `/local/path/to/<os>/packages:/irods_packages` lines.  For the iRODS server entry, you will also need to uncomment the `volumes:` line.
2. For each of the `globus.<os>.Dockerfile` files for the platforms that are to be tested, comment out the lines that install the irods-icommands and irods-dev(el) packages.
3. Uncomment the installation line in the `install_local_irods_client_packages_<os>.sh` files for the platforms that are to be tested. Update the version number in the deb and rpm package filenames as necessary.
4. Update `irods.ubuntu22.Dockerfile` and comment out the line that installs the iRODS packages from the iRODS repo.
5. Update `start.irods.ubuntu22.sh` and uncomment the line that installs the locally built iRODS packages.  Update version number as necessary.
 

Test Limitations
----------------

Currently this only runs against a Globus server running Ubuntu 22.  This will be expanded in the future.

The `python run_all_tests.py` command can be run against Globus installations in other operating systems but those will need to be set up manually.  Refer to [globus start script](start.globus.ubuntu22.sh) for an example.
