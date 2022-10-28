FROM python:3-alpine

# Set Environment Variables
ENV PUID=1000
ENV PGID=1000
ENV USER=abc

# Add Non-Root User
RUN set -eux; \
  echo "**** create $USER user and $USER group with home directory /opt/sigma ****" && \
  addgroup -S $USER && \
  adduser -u $PUID -s /bin/false -h /opt/sigma -S -G $USER $USER && \
  adduser $USER users

# Add Files
COPY . /opt/sigma/
WORKDIR /opt/sigma/tools

# Install Python Modules
#RUN set -eux; \
  #python -m pip install sigma;

# Use sigma as entrypoint
ENTRYPOINT ["sigmac"]