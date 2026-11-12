#!/bin/sh
# Kernel feature checks, run as the container's process by tests/boot.sh.
# One line per check, "FEATURE <name> PASS|FAIL <detail>"; exits 1 when a
# check fails. The addresses are those of the boot test's user network.
failures=0
r() {
    name=$1
    shift
    out=$("$@" 2>&1)
    rc=$?
    out=$(echo "${out}" | tr '\n' ' ' | cut -c1-400)
    if [ "${rc}" = 0 ]; then
        echo "FEATURE ${name} PASS ${out}"
    else
        echo "FEATURE ${name} FAIL rc=${rc} ${out}"
        failures=$((failures + 1))
    fi
}
# The kernel's link-local address can still be in duplicate address
# detection right after boot; wait up to 3 s for it to settle.
settle_ipv6() {
    i=0
    while [ "${i}" -lt 30 ] && ip -6 addr show dev eth0 | grep -q tentative; do
        sleep 0.1
        i=$((i + 1))
    done
}
r userns_unshare unshare -U -n -m -p -f true
r userns_root_map unshare -U -r id -u
r seccomp_status_line sh -c 'grep Seccomp /proc/self/status'
r seccomp_filter /usr/local/bin/seccomp-test
controllers() {
    c=$(cat /sys/fs/cgroup/cgroup.controllers)
    echo "${c}"
    for x in cpuset cpu io memory hugetlb pids rdma misc; do
        echo " ${c} " | grep -q " ${x} " || return 1
    done
}
r cgroup2_controllers controllers
# The process's cgroup namespace root holds its processes, so, as in a
# Docker container (docker-in-docker's entrypoint does the same), they
# move into a child cgroup before the root's controllers are delegated.
cgroup_child() {
    mkdir -p /sys/fs/cgroup/init
    while read -r pid; do
        echo "${pid}" > /sys/fs/cgroup/init/cgroup.procs 2> /dev/null || true
    done < /sys/fs/cgroup/cgroup.procs
    echo "+memory +pids +cpu +io" > /sys/fs/cgroup/cgroup.subtree_control &&
        mkdir -p /sys/fs/cgroup/t &&
        echo 64M > /sys/fs/cgroup/t/memory.max &&
        cat /sys/fs/cgroup/t/memory.max &&
        rmdir /sys/fs/cgroup/t
}
r cgroup2_child cgroup_child
r overlayfs sh -c 'mkdir -p /tmp/o/l /tmp/o/u /tmp/o/w /tmp/o/m && echo lower > /tmp/o/l/f && mount -t overlay overlay -o lowerdir=/tmp/o/l,upperdir=/tmp/o/u,workdir=/tmp/o/w /tmp/o/m && cat /tmp/o/m/f && echo up > /tmp/o/m/g && ls /tmp/o/u && umount /tmp/o/m'
r dev_fuse sh -c 'test -c /dev/fuse && ls -l /dev/fuse'
r wireguard sh -c 'ip link add wg0 type wireguard && ip -d link show wg0 | head -3 && ip link del wg0'
r nft_nat_masquerade sh -c 'nft add table ip nat && nft add chain ip nat postrouting "{ type nat hook postrouting priority 100; }" && nft add rule ip nat postrouting oifname eth0 masquerade && nft add table inet filter && nft add chain inet filter input "{ type filter hook input priority 0; }" && nft add rule inet filter input ct state established,related accept && nft list ruleset && nft flush ruleset'
r iptables_nft_nat_list iptables-nft -t nat -L -n
r iptables_nft_rules sh -c 'iptables-nft -t nat -A POSTROUTING -o eth0 -j MASQUERADE && iptables-nft -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && iptables-nft -A INPUT -p tcp -m multiport --dports 22,80 -m comment --comment check -j ACCEPT && iptables-nft -A FORWARD -i wg+ -j ACCEPT && iptables-nft -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu && iptables-nft -t nat -A PREROUTING -p udp --dport 51820 -j DNAT --to-destination 10.0.0.2 && ip6tables-nft -t nat -A POSTROUTING -o eth0 -j MASQUERADE && iptables-nft-save | grep -c -- "-A" && iptables-nft -t nat -F && iptables-nft -F && ip6tables-nft -t nat -F'
settle_ipv6
r ipv6_eth0 sh -c 'ip -6 addr show dev eth0 | grep -E "inet6 fd15:115::15" && ! ip -6 addr show dev eth0 | grep -q tentative'
r ipv6_link_local_ping sh -c 'ping -6 -c 1 -W 2 ff02::1%eth0 | head -3'
r ipv6_gateway_ping ping -6 -c 1 -W 2 fd15:115::1
r ipv4_gateway_ping ping -c 1 -W 2 10.115.0.1
r dev_kvm_absent sh -c '! test -e /dev/kvm'
r tun sh -c 'test -c /dev/net/tun || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }; ip tuntap add dev tun0 mode tun && ip link del tun0'
r veth_bridge sh -c 'ip link add v0 type veth peer name v1 && ip link add br0 type bridge && ip link set v0 master br0 && ip link del br0 && ip link del v0'
# A router's traffic shaping: the fair queue, ifb, and the fw, u32 and
# flower classifiers with the skbedit and mirred actions, on a dummy link
# (ifb0 and ifb1 are the kernel's own, made at boot).
r tc_sfq sh -c 'ip link add d0 type dummy && tc qdisc add dev d0 root sfq perturb 10 && tc qdisc show dev d0 | grep -q sfq && ip link del d0'
r ifb sh -c 'ip link add ifb9 type ifb && ip link set ifb9 up && ip link del ifb9'
r ifb_made_at_boot sh -c 'ip link show ifb0 | grep -q "state DOWN" && ip link show ifb1 | grep -q "state DOWN" && ! ip link show ifb2 2> /dev/null'
r tc_fw_skbedit sh -c 'ip link add d0 type dummy && tc qdisc add dev d0 root handle 1: htb && tc class add dev d0 parent 1: classid 1:1 htb rate 10mbit && tc filter add dev d0 parent 1: protocol ip prio 1 handle 7 fw flowid 1:1 action skbedit priority 1:1 && tc filter show dev d0 | grep -q skbedit && ip link del d0'
r tc_u32_mirred sh -c 'ip link add d0 type dummy && ip link add ifb9 type ifb && tc qdisc add dev d0 ingress && tc filter add dev d0 parent ffff: protocol ip prio 1 u32 match ip dst 10.0.0.0/8 action mirred egress redirect dev ifb9 && tc filter show dev d0 parent ffff: | grep -q mirred && ip link del d0 && ip link del ifb9'
r tc_flower_mirred sh -c 'ip link add d0 type dummy && ip link add ifb9 type ifb && tc qdisc add dev d0 clsact && tc filter add dev d0 ingress protocol ip flower dst_ip 10.0.0.1 action skbedit mark 5 pipe action mirred egress redirect dev ifb9 && tc filter show dev d0 ingress | grep -q flower && ip link del d0 && ip link del ifb9'
# The host guest bridge's ingress drop (item 235a): a match-all filter
# with a drop action at a clsact ingress, as the agent installs it.
r tc_matchall_drop sh -c 'ip link add d0 type dummy && tc qdisc replace dev d0 clsact && tc filter add dev d0 ingress pref 1 handle 1 protocol all matchall action drop && tc -json filter show dev d0 ingress | grep -q gact && ip link del d0'
# No MPTCP (item 253): no /proc/sys/net/mptcp, and an MPTCP socket is
# refused with EPROTONOSUPPORT, which Go's listeners fall back on.
r no_mptcp sh -c '! test -e /proc/sys/net/mptcp && /usr/local/bin/mptcp-test'
# The machine's own namespace has the fallback tunnel tunl0, a namespace
# made later none (net.core.fb_tunnels_only_for_init_net).
r tunl0_only_in_the_machine sh -c 'ip link show tunl0 > /dev/null && grep -q -x 1 /proc/sys/net/core/fb_tunnels_only_for_init_net && unshare -n sh -c "! ip link show tunl0 2> /dev/null && ip link show lo > /dev/null"'
r modules_off sh -c '! test -e /proc/modules'
r kernel_version sh -c 'uname -r | grep -x "[0-9.]*-ghostrack-container"'
echo "FEATURES failed=${failures}"
[ "${failures}" = 0 ]
