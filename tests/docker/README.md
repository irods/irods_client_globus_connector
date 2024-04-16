Test Framework
==============

This is a test framework for testing the irods_client_globus_connector.

Running Tests
-------------

To run the tests first make sure you have the code that is to be tested checked out.

Run the tests by executing the following in this directory:

```
docker-compose build
docker-compose run globus
```

Test Limitations
----------------

Currently this only runs against a Globus server running Ubuntu 22.  This will be expanded in the future.

The `python run_all_tests.py` command can be run against Globus installations in other operating systems but those will need to be set up manually.  Refer to [globus start script](start.globus.ubuntu22.sh) for an example.
