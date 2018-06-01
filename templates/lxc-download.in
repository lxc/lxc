#!/bin/sh

# Client script for LXC container images.
#
# Copyright © 2014 Stéphane Graber <stgraber@ubuntu.com>
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.

#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.

#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
#  USA

set -eu

LOCALSTATEDIR="@LOCALSTATEDIR@"
LXC_HOOK_DIR="@LXCHOOKDIR@"
LXC_TEMPLATE_CONFIG="@LXCTEMPLATECONFIG@"

# Defaults
DOWNLOAD_ARCH=
DOWNLOAD_BUILD=
DOWNLOAD_COMPAT_LEVEL=5
DOWNLOAD_DIST=
DOWNLOAD_FLUSH_CACHE="false"
DOWNLOAD_FORCE_CACHE="false"
DOWNLOAD_INTERACTIVE="false"
DOWNLOAD_KEYID="0xE7FB0CAEC8173D669066514CBAEFF88C22F6E216"
DOWNLOAD_LIST_IMAGES="false"
DOWNLOAD_MODE="system"
DOWNLOAD_READY_GPG="false"
DOWNLOAD_RELEASE=
DOWNLOAD_SERVER="images.linuxcontainers.org"
DOWNLOAD_SHOW_GPG_WARNING="true"
DOWNLOAD_SHOW_HTTP_WARNING="true"
DOWNLOAD_TARGET="system"
DOWNLOAD_URL=
DOWNLOAD_USE_CACHE="false"
DOWNLOAD_VALIDATE="true"
DOWNLOAD_VARIANT="default"
DOWNLOAD_TEMP=

LXC_MAPPED_GID=
LXC_MAPPED_UID=
LXC_NAME=
LXC_PATH=
LXC_ROOTFS=

if [ -z "${DOWNLOAD_KEYSERVER:-}" ]; then
  DOWNLOAD_KEYSERVER="hkp://pool.sks-keyservers.net"

  # Deal with GPG over http proxy
  if [ -n "${http_proxy:-}" ]; then
    DOWNLOAD_KEYSERVER="hkp://p80.pool.sks-keyservers.net:80"
  fi
fi

# Make sure the usual locations are in PATH
export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin

# Some useful functions
cleanup() {
  if [ -d "${DOWNLOAD_TEMP}" ]; then
    rm -Rf "${DOWNLOAD_TEMP}"
  fi
}

wget_wrapper() {
  for _ in $(seq 3); do
    if wget "$@"; then
      return 0
    fi
  done

  return 1
}

download_file() {
  if ! wget_wrapper -T 30 -q "https://${DOWNLOAD_SERVER}/$1" -O "$2" >/dev/null 2>&1; then
    if ! wget_wrapper -T 30 -q "http://${DOWNLOAD_SERVER}/$1" -O "$2" >/dev/null 2>&1; then
      if [ "$3" = "noexit" ]; then
        return 1
      else
        echo "ERROR: Failed to download http://${DOWNLOAD_SERVER}/$1" 1>&2
        exit 1
      fi
    elif [ "${DOWNLOAD_SHOW_HTTP_WARNING}" = "true" ]; then
      DOWNLOAD_SHOW_HTTP_WARNING="false"
      echo "WARNING: Failed to download the file over HTTPs" 1>&2
      echo "         The file was instead download over HTTP " 1>&2
      echo "A server replay attack may be possible!" 1>&2
    fi
  fi
}

download_sig() {
  if ! download_file "$1" "$2" noexit; then
    if [ "${DOWNLOAD_VALIDATE}" = "true" ]; then
      if [ "$3" = "normal" ]; then
        echo "ERROR: Failed to download http://${DOWNLOAD_SERVER}/$1" 1>&2
        exit 1
      else
        return 1
      fi
    else
      return 0
    fi
  fi
}

gpg_setup() {
  if [ "${DOWNLOAD_VALIDATE}" = "false" ]; then
    return
  fi

  if [ "${DOWNLOAD_READY_GPG}" = "true" ]; then
    return
  fi

  echo "Setting up the GPG keyring"

  mkdir -p "${DOWNLOAD_TEMP}/gpg"
  chmod 700 "${DOWNLOAD_TEMP}/gpg"
  export GNUPGHOME="${DOWNLOAD_TEMP}/gpg"

  success=
  for _ in $(seq 3); do
    if gpg --keyserver "${DOWNLOAD_KEYSERVER}" \
      --recv-keys "${DOWNLOAD_KEYID}" >/dev/null 2>&1; then
      success=1
      break
    fi
    break
  done

  if [ -z "${success}" ]; then
    echo "ERROR: Unable to fetch GPG key from keyserver"
    exit 1
  fi

  DOWNLOAD_READY_GPG="true"
}

gpg_validate() {
  if [ "${DOWNLOAD_VALIDATE}" = "false" ]; then
    if [ "${DOWNLOAD_SHOW_GPG_WARNING}" = "true" ]; then
      echo "WARNING: Running without gpg validation!" 1>&2
    fi
    DOWNLOAD_SHOW_GPG_WARNING="false"
    return 0
  fi

  if ! gpg --verify "$1" >/dev/null 2>&1; then
    echo "ERROR: Invalid signature for $1" 1>&2
    exit 1
  fi
}

in_userns() {
  [ -e /proc/self/uid_map ] || { echo no; return; }
  while read -r line; do
    fields="$(echo "$line" | awk '{ print $1 " " $2 " " $3 }')"
    if [ "${fields}" = "0 0 4294967295" ]; then
      echo no;
      return;
    fi
    if echo "${fields}" | grep -q " 0 1$"; then
      echo userns-root;
      return;
    fi
  done < /proc/self/uid_map

  [ "$(cat /proc/self/uid_map)" = "$(cat /proc/1/uid_map)" ] && { echo userns-root; return; }
  echo yes
}

relevant_file() {
  FILE_PATH="${LXC_CACHE_PATH}/$1"

  if [ -e "${FILE_PATH}-${DOWNLOAD_MODE}" ]; then
    FILE_PATH="${FILE_PATH}-${DOWNLOAD_MODE}"
  fi

  if [ -e "${FILE_PATH}.${DOWNLOAD_COMPAT_LEVEL}" ]; then
    FILE_PATH="${FILE_PATH}.${DOWNLOAD_COMPAT_LEVEL}"
  fi

  echo "${FILE_PATH}"
}

usage() {
  cat <<EOF
LXC container image downloader

Special arguments:
[ -h | --help ]: Print this help message and exit
[ -l | --list ]: List all available images and exit

Required arguments:
[ -d | --dist <distribution> ]: The name of the distribution
[ -r | --release <release> ]: Release name/version
[ -a | --arch <architecture> ]: Architecture of the container

Optional arguments:
[ --variant <variant> ]: Variant of the image (default: "default")
[ --server <server> ]: Image server (default: "images.linuxcontainers.org")
[ --keyid <keyid> ]: GPG keyid (default: 0x...)
[ --keyserver <keyserver> ]: GPG keyserver to use. Environment variable: DOWNLOAD_KEYSERVER
[ --no-validate ]: Disable GPG validation (not recommended)
[ --flush-cache ]: Flush the local copy (if present)
[ --force-cache ]: Force the use of the local copy even if expired

LXC internal arguments (do not pass manually!):
[ --name <name> ]: The container name
[ --path <path> ]: The path to the container
[ --rootfs <rootfs> ]: The path to the container's rootfs
[ --mapped-uid <map> ]: A uid map (user namespaces)
[ --mapped-gid <map> ]: A gid map (user namespaces)

Environment Variables:
DOWNLOAD_KEYSERVER : The URL of the key server to use, instead of the default.
                     Can be further overridden by using optional argument --keyserver

EOF
  return 0
}

if ! options=$(getopt -o d:r:a:hl -l dist:,release:,arch:,help,list,variant:,\
server:,keyid:,keyserver:,no-validate,flush-cache,force-cache,name:,path:,\
rootfs:,mapped-uid:,mapped-gid: -- "$@"); then
  usage
  exit 1
fi
eval set -- "$options"

while :; do
  case "$1" in
    -h|--help)     usage && exit 1;;
    -l|--list)     DOWNLOAD_LIST_IMAGES="true"; shift 1;;
    -d|--dist)     DOWNLOAD_DIST="$2"; shift 2;;
    -r|--release)  DOWNLOAD_RELEASE="$2"; shift 2;;
    -a|--arch)     DOWNLOAD_ARCH="$2"; shift 2;;
    --variant)     DOWNLOAD_VARIANT="$2"; shift 2;;
    --server)      DOWNLOAD_SERVER="$2"; shift 2;;
    --keyid)       DOWNLOAD_KEYID="$2"; shift 2;;
    --keyserver)   DOWNLOAD_KEYSERVER="$2"; shift 2;;
    --no-validate) DOWNLOAD_VALIDATE="false"; shift 1;;
    --flush-cache) DOWNLOAD_FLUSH_CACHE="true"; shift 1;;
    --force-cache) DOWNLOAD_FORCE_CACHE="true"; shift 1;;
    --name)        LXC_NAME="$2"; shift 2;;
    --path)        LXC_PATH="$2"; shift 2;;
    --rootfs)      LXC_ROOTFS="$2"; shift 2;;
    --mapped-uid)  LXC_MAPPED_UID="$2"; shift 2;;
    --mapped-gid)  LXC_MAPPED_GID="$2"; shift 2;;
    *)             break;;
  esac
done

# Check for required binaries
for bin in tar xz wget; do
  if ! command -V "${bin}" >/dev/null 2>&1; then
    echo "ERROR: Missing required tool: ${bin}" 1>&2
    exit 1
  fi
done

# Check for GPG
if [ "${DOWNLOAD_VALIDATE}" = "true" ]; then
  if ! command -V gpg >/dev/null 2>&1; then
    echo "ERROR: Missing recommended tool: gpg" 1>&2
    echo "You can workaround this by using --no-validate" 1>&2
    exit 1
  fi
fi

# Check that we have all variables we need
if [ -z "${LXC_NAME}" ] || [ -z "${LXC_PATH}" ] || [ -z "${LXC_ROOTFS}" ]; then
  if [ "${DOWNLOAD_LIST_IMAGES}" != "true" ]; then
    echo "ERROR: Please pass the name, path, and rootfs for the container" 1>&2
    exit 1
  fi
fi

USERNS="$(in_userns)"

if [ "${USERNS}" != "no" ]; then
  if [ "${USERNS}" = "yes" ]; then
    if [ -z "${LXC_MAPPED_UID}" ] || [ "${LXC_MAPPED_UID}" = "-1" ]; then
      echo "ERROR: In a user namespace without a map" 1>&2
      exit 1
    fi
    DOWNLOAD_MODE="user"
    DOWNLOAD_TARGET="user"
  else
    DOWNLOAD_MODE="user"
    DOWNLOAD_TARGET="system"
  fi
fi

if [ -z "${DOWNLOAD_DIST}" ] || [ -z "${DOWNLOAD_RELEASE}" ] || [ -z "${DOWNLOAD_ARCH}" ]; then
  DOWNLOAD_INTERACTIVE="true"
fi

# Trap all exit signals
trap cleanup EXIT HUP INT TERM

# /tmp may be mounted in tmpfs or noexec
if mountpoint -q /tmp; then
  DOWNLOAD_TEMP="${LXC_PATH}"
fi

if ! command -V mktemp >/dev/null 2>&1; then
  DOWNLOAD_TEMP="${DOWNLOAD_TEMP}/tmp/lxc-download.$$"
elif [ -n "${DOWNLOAD_TEMP}" ]; then
  mkdir -p "${DOWNLOAD_TEMP}"
  DOWNLOAD_TEMP="$(mktemp -p ${DOWNLOAD_TEMP} -d)"
else
  DOWNLOAD_TEMP="${DOWNLOAD_TEMP}$(mktemp -d)"
fi

# Simply list images
if [ "${DOWNLOAD_LIST_IMAGES}" = "true" ] || [ "${DOWNLOAD_INTERACTIVE}" = "true" ]; then
  # Initialize GPG
  gpg_setup

  # Grab the index
  DOWNLOAD_INDEX_PATH="/meta/1.0/index-${DOWNLOAD_MODE}"

  echo "Downloading the image index"
  if ! download_file "${DOWNLOAD_INDEX_PATH}.${DOWNLOAD_COMPAT_LEVEL}" "${DOWNLOAD_TEMP}/index" noexit ||
     ! download_sig "${DOWNLOAD_INDEX_PATH}.${DOWNLOAD_COMPAT_LEVEL}.asc" "${DOWNLOAD_TEMP}/index.asc" noexit; then
    download_file "${DOWNLOAD_INDEX_PATH}" "${DOWNLOAD_TEMP}/index" normal
    download_sig "${DOWNLOAD_INDEX_PATH}.asc" "${DOWNLOAD_TEMP}/index.asc" normal
  fi

  gpg_validate "${DOWNLOAD_TEMP}/index.asc"

  # Parse it
  echo ""
  echo "---"
  printf "DIST\tRELEASE\tARCH\tVARIANT\tBUILD\n"
  echo "---"
  while IFS=';' read -r f1 f2 f3 f4 f5 f6; do
    [ -n "${DOWNLOAD_DIST}" ] && [ "$f1" != "${DOWNLOAD_DIST}" ] && continue
    [ -n "${DOWNLOAD_RELEASE}" ] && [ "$f2" != "${DOWNLOAD_RELEASE}" ] && continue
    [ -n "${DOWNLOAD_ARCH}" ] && [ "$f3" != "${DOWNLOAD_ARCH}" ] && continue
    [ -n "${DOWNLOAD_VARIANT}" ] && [ "$f4" != "${DOWNLOAD_VARIANT}" ] && continue
    [ -z "${f5}" ] || [ -z "${f6}" ] && continue

    printf "%s\t%s\t%s\t%s\t%s\n" "${f1}" "${f2}" "${f3}" "${f4}" "${f5}"
    unset f1 f2 f3 f4 f5 f6
  done < "${DOWNLOAD_TEMP}/index"
  echo "---"

  if [ "${DOWNLOAD_LIST_IMAGES}" = "true" ]; then
    exit 1
  fi

  # Interactive mode
  echo ""

  if [ -z "${DOWNLOAD_DIST}" ]; then
    echo "Distribution: "
    read -r DOWNLOAD_DIST
  fi

  if [ -z "${DOWNLOAD_RELEASE}" ]; then
    echo "Release: "
    read -r DOWNLOAD_RELEASE
  fi

  if [ -z "${DOWNLOAD_ARCH}" ]; then
    echo "Architecture: "
    read -r DOWNLOAD_ARCH
  fi

  echo ""
fi

# Setup the cache
if [ "${DOWNLOAD_TARGET}" = "system" ]; then
  LXC_CACHE_BASE="${LOCALSTATEDIR}/cache/lxc/"
else
  LXC_CACHE_BASE="${HOME}/.cache/lxc/"
fi

# Allow the setting of the LXC_CACHE_PATH with the usage of environment variables.
LXC_CACHE_PATH="${LXC_CACHE_PATH:-"${LXC_CACHE_BASE}"}"
LXC_CACHE_PATH="${LXC_CACHE_PATH}/download/${DOWNLOAD_DIST}"
LXC_CACHE_PATH="${LXC_CACHE_PATH}/${DOWNLOAD_RELEASE}/${DOWNLOAD_ARCH}/"
LXC_CACHE_PATH="${LXC_CACHE_PATH}/${DOWNLOAD_VARIANT}"

if [ -d "${LXC_CACHE_PATH}" ]; then
  if [ "${DOWNLOAD_FLUSH_CACHE}" = "true" ]; then
    echo "Flushing the cache..."
    rm -Rf "${LXC_CACHE_PATH}"
  elif [ "${DOWNLOAD_FORCE_CACHE}" = "true" ]; then
    DOWNLOAD_USE_CACHE="true"
  else
    DOWNLOAD_USE_CACHE="true"
    if [ -e "$(relevant_file expiry)" ]; then
      if [ "$(cat "$(relevant_file expiry)")" -lt "$(date +%s)" ]; then
        echo "The cached copy has expired, re-downloading..."
        DOWNLOAD_USE_CACHE="false"
      fi
    fi
  fi
fi

# Download what's needed
if [ "${DOWNLOAD_USE_CACHE}" = "false" ]; then
  # Initialize GPG
  gpg_setup

  # Grab the index
  DOWNLOAD_INDEX_PATH="/meta/1.0/index-${DOWNLOAD_MODE}"

  echo "Downloading the image index"
  if ! download_file "${DOWNLOAD_INDEX_PATH}.${DOWNLOAD_COMPAT_LEVEL}" "${DOWNLOAD_TEMP}/index" noexit ||
     ! download_sig "${DOWNLOAD_INDEX_PATH}.${DOWNLOAD_COMPAT_LEVEL}.asc" "${DOWNLOAD_TEMP}/index.asc" noexit; then
    download_file "${DOWNLOAD_INDEX_PATH}" "${DOWNLOAD_TEMP}/index" normal
    download_sig "${DOWNLOAD_INDEX_PATH}.asc" "${DOWNLOAD_TEMP}/index.asc" normal
  fi

  gpg_validate "${DOWNLOAD_TEMP}/index.asc"

  # Parse it
  while IFS=';' read -r f1 f2 f3 f4 f5 f6; do
    if [ "${f1}" != "${DOWNLOAD_DIST}" ] || \
       [ "${f2}" != "${DOWNLOAD_RELEASE}" ] || \
       [ "${f3}" != "${DOWNLOAD_ARCH}" ] || \
       [ "${f4}" != "${DOWNLOAD_VARIANT}" ] || \
       [ -z "${f6}" ]; then
        continue
    fi

    DOWNLOAD_BUILD="${f5}"
    DOWNLOAD_URL="${f6}"

    unset f1 f2 f3 f4 f5 f6
    break
  done < "${DOWNLOAD_TEMP}/index"

  if [ -z "${DOWNLOAD_URL}" ]; then
    echo "ERROR: Couldn't find a matching image" 1>&1
    exit 1
  fi

  if [ -d "${LXC_CACHE_PATH}" ] && [ -f "${LXC_CACHE_PATH}/build_id" ] && \
     [ "$(cat "${LXC_CACHE_PATH}/build_id")" = "${DOWNLOAD_BUILD}" ]; then
    echo "The cache is already up to date"
    echo "Using image from local cache"
  else
    # Download the actual files
    echo "Downloading the rootfs"
    download_file "${DOWNLOAD_URL}/rootfs.tar.xz" "${DOWNLOAD_TEMP}/rootfs.tar.xz" normal
    download_sig "${DOWNLOAD_URL}/rootfs.tar.xz.asc" "${DOWNLOAD_TEMP}/rootfs.tar.xz.asc" normal
    gpg_validate "${DOWNLOAD_TEMP}/rootfs.tar.xz.asc"

    echo "Downloading the metadata"
    download_file "${DOWNLOAD_URL}/meta.tar.xz" "${DOWNLOAD_TEMP}/meta.tar.xz" normal
    download_sig "$DOWNLOAD_URL/meta.tar.xz.asc" "${DOWNLOAD_TEMP}/meta.tar.xz.asc" normal
    gpg_validate "${DOWNLOAD_TEMP}/meta.tar.xz.asc"

    if [ -d "${LXC_CACHE_PATH}" ]; then
      rm -Rf "${LXC_CACHE_PATH}"
    fi
    mkdir -p "${LXC_CACHE_PATH}"
    mv "${DOWNLOAD_TEMP}/rootfs.tar.xz" "${LXC_CACHE_PATH}"
    if ! tar Jxf "${DOWNLOAD_TEMP}/meta.tar.xz" -C "${LXC_CACHE_PATH}"; then
      echo "ERROR: Invalid rootfs tarball." 2>&1
      exit 1
    fi

    echo "${DOWNLOAD_BUILD}" > "${LXC_CACHE_PATH}/build_id"

    if [ -n "${LXC_MAPPED_UID}" ] && [ "${LXC_MAPPED_UID}" != "-1" ]; then
      # As the script is run in strict mode (set -eu), all commands
      # exiting with non 0 would make the script stop.
      # || true or || : (more portable) prevents that.
      chown -R "${LXC_MAPPED_UID}" "${LXC_CACHE_BASE}" >/dev/null 2>&1 || :
    fi
    if [ -n "${LXC_MAPPED_GID}" ] && [ "${LXC_MAPPED_GID}" != "-1" ]; then
      chgrp -R "${LXC_MAPPED_GID}" "${LXC_CACHE_BASE}" >/dev/null 2>&1 || :
    fi
    echo "The image cache is now ready"
  fi
else
  echo "Using image from local cache"
fi

# Unpack the rootfs
echo "Unpacking the rootfs"

EXCLUDES=""
excludelist=$(relevant_file excludes)
if [ -f "${excludelist}" ]; then
  while read -r line; do
    EXCLUDES="${EXCLUDES} --exclude=${line}"
  done < "${excludelist}"
fi

# Do not surround ${EXCLUDES} by quotes. This does not work. The solution could
# use array but this is not POSIX compliant. The only POSIX compliant solution
# is to use a function wrapper, but the latter can't be used here as the args
# are dynamic. We thus need to ignore the warning brought by shellcheck.
# shellcheck disable=SC2086
tar  --anchored ${EXCLUDES} --numeric-owner -xpJf "${LXC_CACHE_PATH}/rootfs.tar.xz" -C "${LXC_ROOTFS}"

mkdir -p "${LXC_ROOTFS}/dev/pts/"

# Setup the configuration
configfile="$(relevant_file config)"
fstab="$(relevant_file fstab)"
if [ ! -e "${configfile}" ]; then
  echo "ERROR: meta tarball is missing the configuration file" 1>&2
  exit 1
fi

## Extract all the network config entries
sed -i -e "/lxc.net.0/{w ${LXC_PATH}/config-network" -e "d}" "${LXC_PATH}/config"

## Extract any other config entry
sed -i -e "/lxc./{w ${LXC_PATH}/config-auto" -e "d}" "${LXC_PATH}/config"

## Append the defaults
{
  echo ""
  echo "# Distribution configuration"
  cat "$configfile"
} >> "${LXC_PATH}/config"

## Add the container-specific config
{
  echo ""
  echo "# Container specific configuration"
  if [ -e "${LXC_PATH}/config-auto" ]; then
    cat "${LXC_PATH}/config-auto"
    rm "${LXC_PATH}/config-auto"
  fi
  if [ -e "${fstab}" ]; then
    echo "lxc.mount.fstab = ${LXC_PATH}/fstab"
  fi
  echo "lxc.uts.name = ${LXC_NAME}"
} >> "${LXC_PATH}/config"

## Re-add the previously removed network config
if [ -e "${LXC_PATH}/config-network" ]; then
  {
    echo ""
    echo "# Network configuration"
    cat "${LXC_PATH}/config-network"
    rm "${LXC_PATH}/config-network"
  } >> "${LXC_PATH}/config"
fi

TEMPLATE_FILES="${LXC_PATH}/config"

# Setup the fstab
if [ -e "${fstab}" ]; then
  cp "${fstab}" "${LXC_PATH}/fstab"
  TEMPLATE_FILES="${TEMPLATE_FILES};${LXC_PATH}/fstab"
fi

# Look for extra templates
if [ -e "$(relevant_file templates)" ]; then
  while read -r line; do
    fullpath="${LXC_ROOTFS}/${line}"
    [ ! -e "${fullpath}" ] && continue
    TEMPLATE_FILES="${TEMPLATE_FILES};${fullpath}"
  done < "$(relevant_file templates)"
fi

# Replace variables in all templates
OLD_IFS=${IFS}
IFS=";"
for file in ${TEMPLATE_FILES}; do
    [ ! -f "${file}" ] && continue
  sed -i "s#LXC_NAME#${LXC_NAME}#g" "${file}"
  sed -i "s#LXC_PATH#${LXC_PATH}#g" "${file}"
  sed -i "s#LXC_ROOTFS#${LXC_ROOTFS}#g" "${file}"
  sed -i "s#LXC_TEMPLATE_CONFIG#${LXC_TEMPLATE_CONFIG}#g" "${file}"
  sed -i "s#LXC_HOOK_DIR#${LXC_HOOK_DIR}#g" "${file}"
done
IFS=${OLD_IFS}

# prevent mingetty from calling vhangup(2) since it fails with userns on CentOS / Oracle
if [ -f "${LXC_ROOTFS}/etc/init/tty.conf" ]; then
  sed -i 's|mingetty|mingetty --nohangup|' "${LXC_ROOTFS}/etc/init/tty.conf"
fi

if [ -n "${LXC_MAPPED_UID}" ] && [ "${LXC_MAPPED_UID}" != "-1" ]; then
  chown "${LXC_MAPPED_UID}" "${LXC_PATH}/config" "${LXC_PATH}/fstab" >/dev/null 2>&1 || :
fi

if [ -n "${LXC_MAPPED_GID}" ] && [ "${LXC_MAPPED_GID}" != "-1" ]; then
  chgrp "${LXC_MAPPED_GID}" "${LXC_PATH}/config" "${LXC_PATH}/fstab" >/dev/null 2>&1 || :
fi

if [ -e "$(relevant_file create-message)" ]; then
  echo ""
  echo "---"
  cat "$(relevant_file create-message)"
fi

exit 0
