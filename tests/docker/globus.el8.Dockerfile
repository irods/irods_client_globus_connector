FROM almalinux:8

RUN dnf check-update -q >/dev/null || { [ "$?" -eq 100 ] && dnf update -y; }

RUN \
  dnf install -y \
    pam-devel \
    python3-jsonschema \
    epel-release \
    gcc-c++ \
    gnupg \
    make \
    python3 \
    python3-pip \
    rsyslog \
    sudo \
    which \
    diffutils \
    procps \
    rpm-build \
    authd \
    unixODBC-devel \
  && \
  dnf clean all && \
  rm -rf /var/cache/dnf /var/cache/yum /tmp/*

# python 2 and 3 must be installed separately because dnf will ignore/discard python2
RUN dnf install -y \
    python3 \
    python3-devel \
    python3-pip \
    python3-distro \
    python3-psutil \
    python3-pyodbc \
    python3-jsonschema \
    python3-requests \
  && \
  dnf clean all && \
  rm -rf /var/cache/dnf /var/cache/yum /tmp/*

RUN python3 -m pip --no-cache-dir install xmlrunner

RUN dnf install -y \
        dnf-plugin-config-manager \
    && \
    rpm --import https://packages.irods.org/irods-signing-key.asc && \
    dnf config-manager -y --add-repo https://packages.irods.org/renci-irods.yum.repo && \
    dnf config-manager -y --set-enabled renci-irods && \
    rpm --import https://core-dev.irods.org/irods-core-dev-signing-key.asc && \
    dnf config-manager -y --add-repo https://core-dev.irods.org/renci-irods-core-dev.yum.repo && \
    dnf config-manager -y --set-enabled renci-irods-core-dev && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/*

#### Get and install globus repo ####
RUN dnf -y install https://downloads.globus.org/globus-connect-server/stable/installers/repo/rpm/globus-repo-latest.noarch.rpm && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/*

#### Install and configure globus specific things ####
RUN dnf install -y globus-gridftp-server-progs \
    globus-simple-ca \
    globus-gass-copy-progs \
    globus-gsi-cert-utils-progs \
    globus-proxy-utils \
    && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/*

# Disabling repo for epel because it does not grab the newest developoment packages which are
# needed to build the Globus plugin. 
RUN dnf --disablerepo epel install -y globus-common-devel \
    globus-gridftp-server-devel \
    globus-gridmap-callout-error-devel \
    && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/*

RUN mkdir /iRODS_DSI && chmod 777 /iRODS_DSI

#### Install icommands - used to set up, validate and tear down tests. ####
#### Install externals and dev package to build the connector.         ####

# Comment out the irods-icommands and irods-devel if testing against locally
# built packages.
RUN dnf install -y \
    irods-icommands \
    irods-devel \
    irods-externals-cmake3.21.4-0 \
    irods-externals-clang13.0.1-0 \
    irods-externals-clang-runtime13.0.1-0 \
    && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/*

COPY start.globus.run.tests.el.sh /
RUN chmod u+x /start.globus.run.tests.el.sh

COPY install_local_irods_client_packages_el8.sh /install_local_irods_packages.sh
RUN chmod u+x /install_local_irods_packages.sh

ENTRYPOINT "/start.globus.run.tests.el.sh"
