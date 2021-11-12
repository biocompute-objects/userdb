# userdb
This is one of two API for the [BioCompute Portal](https://github.com/biocompute-objects/portal). 

# Using Docker with the BCO UserDatabase

### Building the BCO UserDatabase via Docker

A docker file is provided to allow easy building of the BCO UserDatabase.  This can be done from the root directory (the directory with Dockerfile in it) by running:

`docker build -t userdb:latest .`

This will build a container named `userdb` with the tag `latest`.

### Running the container via Docker

The BCO UserDatabase container can be run via docker on the command line by running:

`docker run --rm --network host -it userdb:latest`

This will expose the server at `http://127.0.0.1:8080`.

#### Overriding the port

It is possible to override the port `8080` to whatever port is desired, for example port `8008`.  This is done by running the container:

`docker run --rm --network host -it userdb:latest 0.0.0.0:8008`

NOTE: The ip address of `0.0.0.0` is to allow the web serer to properly associate with `127.0.0.1` - if given `127.0.0.1` it will not allow communications outside of the container!

With `8008` representing the desired port.  You can also give it a specific network created with `docker network create` if you wanted to give assigned IP addresses.

