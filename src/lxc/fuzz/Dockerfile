FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool pkgconf
RUN git clone --depth 1 https://github.com/lxc/lxc.git lxc
WORKDIR lxc
COPY build.sh $SRC/