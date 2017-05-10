#!/bin/bash
#
#lxc.network.script.args = br10 vlan52
# or
#lxc.network.script.args = br10 trunk53

BRIDGE="${6}"
VLAN="${7}"

case "$3" in
up)
	[ -n "$BRIDGE" ] || exit 1

	ovs-vsctl --may-exist add-br $BRIDGE
	ovs-vsctl --if-exists del-port $BRIDGE $5
	vcfg=""
	if [ -n "$VLAN" ]; then
		if [ "${VLAN#vlan}" != "${VLAN}" ]; then
			vcfg="tag=${VLAN#vlan}"
		fi
		if [ "${VLAN#trunk}" != "${VLAN}" ]; then
			vcfg="trunks=${VLAN#trunk}"
		fi
	fi
	ovs-vsctl add-port $BRIDGE $5 $vcfg
	;;
down)
	[ -z "$BRIDGE" ] && BRIDGE="`ovs-vsctl port-to-br $5`"
	[ -n "$BRIDGE" ] && ovs-vsctl --if-exists del-port $BRIDGE $5
	;;
esac
