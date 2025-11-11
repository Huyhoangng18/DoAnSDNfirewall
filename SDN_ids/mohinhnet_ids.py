#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

def run():
    net = Mininet(
        controller=RemoteController,
        link=TCLink,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=False
    )

    info('*** Thêm Ryu controller (tcp:127.0.0.1:6653)\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Tạo 2 L2 và 1 L3 switch (OpenFlow13, secure)\n')
    s1  = net.addSwitch('s1',  failMode='secure', protocols='OpenFlow13')
    s2  = net.addSwitch('s2',  failMode='secure', protocols='OpenFlow13')
    sL3 = net.addSwitch('sL3', failMode='secure', protocols='OpenFlow13')

    info('*** Tạo hosts\n')
    h1 = net.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    h3 = net.addHost('h3', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h4 = net.addHost('h4', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
    hX = net.addHost('hX', ip='192.168.10.100/24', defaultRoute='via 192.168.10.1')

    info('*** Nối host vào L2\n')
    l_h1_s1 = net.addLink(h1, s1)
    l_h2_s1 = net.addLink(h2, s1)
    l_h3_s2 = net.addLink(h3, s2)
    l_h4_s2 = net.addLink(h4, s2)

    info('*** Uplink L2 -> L3 và host ngoài -> L3\n')
    l_s1_sL3 = net.addLink(s1, sL3)    # Dept1 uplink
    l_s2_sL3 = net.addLink(s2, sL3)    # Dept2 uplink
    l_hX_sL3 = net.addLink(hX, sL3)    # hX vào L3

    net.start()

    info('*** Ép OVS bridge dùng OpenFlow13 (phòng hờ)\n')
    for br in ('s1', 's2', 'sL3'):
        net[br].cmd(f'ovs-vsctl set bridge {br} protocols=OpenFlow13')

    info('*** Tạo mirror trên sL3 -> suri0 (port nội bộ cho Suricata)\n')
    # tạo port internal ở bridge sL3 và bật lên (trong root namespace host)
    sL3.cmd('ovs-vsctl --may-exist add-port sL3 suri0 -- set interface suri0 type=internal')
    sL3.cmd('ip link set suri0 up')
    # mirror toàn bộ lưu lượng trên bridge sL3 vào suri0
    sL3.cmd('ovs-vsctl -- --id=@ids get Port suri0 '
            '-- --id=@m create Mirror name=mirror0 select-all=true output-port=@ids '
            '-- add Bridge sL3 mirrors @m')

    info('*** Lấy tên port phía switch để gán VLAN tag\n')
    p_s1_h1 = l_h1_s1.intf2.name
    p_s1_h2 = l_h2_s1.intf2.name
    p_s1_up = l_s1_sL3.intf1.name

    p_s2_h3 = l_h3_s2.intf2.name
    p_s2_h4 = l_h4_s2.intf2.name
    p_s2_up = l_s2_sL3.intf1.name

    p_sL3_to_s1 = l_s1_sL3.intf2.name
    p_sL3_to_s2 = l_s2_sL3.intf2.name
    p_sL3_to_hX = l_hX_sL3.intf2.name

    info('*** Set VLAN access cho toàn bộ port\n')
    # Dept1 = VLAN 101
    s1.cmd(f'ovs-vsctl set port {p_s1_h1} tag=101')
    s1.cmd(f'ovs-vsctl set port {p_s1_h2} tag=101')
    s1.cmd(f'ovs-vsctl set port {p_s1_up} tag=101')
    sL3.cmd(f'ovs-vsctl set port {p_sL3_to_s1} tag=101')

    # Dept2 = VLAN 102
    s2.cmd(f'ovs-vsctl set port {p_s2_h3} tag=102')
    s2.cmd(f'ovs-vsctl set port {p_s2_h4} tag=102')
    s2.cmd(f'ovs-vsctl set port {p_s2_up} tag=102')
    sL3.cmd(f'ovs-vsctl set port {p_sL3_to_s2} tag=102')

    # External = VLAN 200 (access phía sL3)
    sL3.cmd(f'ovs-vsctl set port {p_sL3_to_hX} tag=200')

    info('*** Tạo SVI (internal) trên sL3 + gán IP\n')
    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan101 tag=101 -- set interface sL3-vlan101 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan101')
    sL3.cmd('ip addr add 10.0.1.1/24 dev sL3-vlan101')
    sL3.cmd('ip link set sL3-vlan101 up')

    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan102 tag=102 -- set interface sL3-vlan102 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan102')
    sL3.cmd('ip addr add 10.0.2.1/24 dev sL3-vlan102')
    sL3.cmd('ip link set sL3-vlan102 up')

    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan200 tag=200 -- set interface sL3-vlan200 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan200')
    sL3.cmd('ip addr add 192.168.10.1/24 dev sL3-vlan200')
    sL3.cmd('ip link set sL3-vlan200 up')

    info('*** Bật IP forwarding + cho phép FORWARD\n')
    sL3.cmd('sysctl -w net.ipv4.ip_forward=1')
    sL3.cmd('iptables -P FORWARD ACCEPT')
    sL3.cmd('iptables -F FORWARD')

    info('*** Thử nhanh: ping giữa các VLAN\n')
    net.ping([h1, h3])
    net.ping([h2, hX])

    info('*** CLI để kiểm thử/quan sát flow (giữ mạng & mirror đang chạy)\n')
    CLI(net)

    info('*** Cleanup SVI\n')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan101')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan102')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan200')
    # (tuỳ chọn) gỡ mirror và suri0 khi thoát CLI:
    sL3.cmd('ovs-vsctl -- --id=@m find Mirror name=mirror0 -- remove Bridge sL3 mirrors @m || true')
    sL3.cmd('ovs-vsctl del-port sL3 suri0 || true')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

