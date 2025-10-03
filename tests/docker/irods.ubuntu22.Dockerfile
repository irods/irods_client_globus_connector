FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

#### install basic packages ####
RUN apt-get update && \
    apt-get install -y apt-utils \
    apt-transport-https \
    unixodbc \
    wget \
    lsb-release \
    sudo \
    super \
    lsof \
    postgresql \
    odbc-postgresql \
    libjson-perl \
    gnupg \
    sudo \
    rsyslog \
    g++ \
    cdbs \
    tig \
    git \
    telnet \
    ftp \
    python3 \
    python3-distro \
    python3-psutil \
    python3-jsonschema \
    python3-requests \
    python3-pip \
    python3-pyodbc \
    netcat \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

#### Get and install iRODS repo ####
RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | sudo apt-key add -  && \
    echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/renci-irods.list

#### Install iRODS ####
ENV irods_version 5.0.2-0~jammy

# If testing against locally built packages, comment out the following line.
RUN apt-get update && \
    apt-get install -y irods-server=${irods_version} irods-dev=${irods_version} irods-database-plugin-postgres=${irods_version} irods-runtime=${irods_version} irods-icommands=${irods_version}  && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

#### Set up ICAT database. ####
COPY db_commands.txt /
RUN service postgresql start && su - postgres -c 'psql -f /db_commands.txt'

COPY start.irods.ubuntu22.sh /
RUN chmod u+x /start.irods.ubuntu22.sh
ENTRYPOINT "/start.irods.ubuntu22.sh"
