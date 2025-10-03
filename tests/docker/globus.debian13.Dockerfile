FROM debian:13 

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

#### install basic packages ####
RUN apt-get update && apt-get install -y curl \
    cmake \
    g++ \
    gcc \
    ftp \
    telnet \
    libcurl4-openssl-dev \
    unzip \
    python3 \
    python3-distro \
    python3-psutil \
    python3-jsonschema \
    python3-requests \
    python3-pip \
    python3-pyodbc \
    wget \
    gnupg2 \
    lsb-release \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

#### Get and install iRODS repo ####
RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | \
        gpg \
            --no-options \
            --no-default-keyring \
            --no-auto-check-trustdb \
            --homedir /dev/null \
            --no-keyring \
            --import-options import-export \
            --output /etc/apt/keyrings/renci-irods-archive-keyring.pgp \
            --import \
        && \
    echo "deb [signed-by=/etc/apt/keyrings/renci-irods-archive-keyring.pgp arch=amd64] https://packages.irods.org/apt/ trixie main" | \
        tee /etc/apt/sources.list.d/renci-irods.list && \
    wget -qO - https://core-dev.irods.org/irods-core-dev-signing-key.asc | \
        gpg \
            --no-options \
            --no-default-keyring \
            --no-auto-check-trustdb \
            --homedir /dev/null \
            --no-keyring \
            --import-options import-export \
            --output /etc/apt/keyrings/renci-irods-core-dev-archive-keyring.pgp \
            --import \
        && \
    echo "deb [signed-by=/etc/apt/keyrings/renci-irods-core-dev-archive-keyring.pgp arch=amd64] https://core-dev.irods.org/apt/ trixie main" | \
        tee /etc/apt/sources.list.d/renci-irods-core-dev.list

#### Install icommands - used to set up, validate and tear down tests. ####
#### Install externals and dev package to build the connector.         ####

# Comment out the irods-icommands and irods-dev if testing against locally
# built packages.
RUN apt-get update && apt-get install -y \
    irods-icommands \
    irods-dev \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

#### Get and install globus repo ####
RUN wget -q https://downloads.globus.org/globus-connect-server/stable/installers/repo/deb/globus-repo_latest_all.deb && \
    apt-get update && \
    apt-get install -y ./globus-repo_latest_all.deb && \
    rm ./globus-repo_latest_all.deb \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

#### Install and configure globus specific things ####
RUN apt-get update && apt-get install -y globus-connect-gridftp-server-progs \
    globus-simple-ca \
    globus-gass-copy-progs \
    libglobus-common-dev \
    libglobus-gridftp-server-dev \
    libglobus-gridmap-callout-error-dev \
    globus-gsi-cert-utils-progs \
    globus-proxy-utils \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# Replacement for telnetlib for Python 3.13 and greater
RUN apt-get update && apt install python3-zombie-telnetlib \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

RUN mkdir /iRODS_DSI && chmod 777 /iRODS_DSI

COPY start.globus.run.tests.ubuntu.sh /
RUN chmod u+x /start.globus.run.tests.ubuntu.sh

COPY install_local_irods_client_packages_debian13.sh /install_local_irods_packages.sh
RUN chmod u+x /install_local_irods_packages.sh

ENTRYPOINT "/start.globus.run.tests.ubuntu.sh"
