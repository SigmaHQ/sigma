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
  # Add Sigma Tools via Pip
  #python -m pip install sigmatools

WORKDIR /opt/sigma/

# Add Files
COPY . /opt/sigma/

# Install Python Modules
RUN set -eux; \
  apk update && apk add --no-cache make && \
  make build && \
  cd tools && \
  python -m pip install dist/*.whl && \
  make clean && \
  chown -R abc. /opt/sigma

#USER ["abc"]

# Use sigma as entrypoint
ENTRYPOINT ["sigmac"]
