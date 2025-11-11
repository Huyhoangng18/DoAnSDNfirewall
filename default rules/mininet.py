#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

def run():
    net = Mininet(controller=None, link=TCLink, switch=OVSKernelSwitch,
                  autoSetMacs=True, autoStaticArp=False)

    info('*** Tạo switch L2 cho 2 phòng ban và switch L3\n')
    s1   = net.addSwitch('s1', failMode='standalone')   # Dept1 (VLAN 101)
    s2   = net.addSwitch('s2', failMode='standalone')   # Dept2 (VLAN 102)
    sL3  = net.addSwitch('sL3', failMode='standalone')  # L3 routing (SVI)

    info('*** Tạo hosts\n')
    # Dept1
    h1 = net.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    # Dept2
    h3 = net.addHost('h3', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h4 = net.addHost('h4', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
    # External
    hX = net.addHost('hX', ip='192.168.10.100/24', defaultRoute='via 192.168.10.1')

    info('*** Nối host vào L2 switches\n')
    # Dept1
    l_h1_s1 = net.addLink(h1, s1)
    l_h2_s1 = net.addLink(h2, s1)
    # Dept2
    l_h3_s2 = net.addLink(h3, s2)
    l_h4_s2 = net.addLink(h4, s2)

    info('*** Nối uplink L2 -> L3 và host ngoài -> L3\n')
    l_s1_sL3 = net.addLink(s1, sL3)   # uplink Dept1
    l_s2_sL3 = net.addLink(s2, sL3)   # uplink Dept2
    l_hX_sL3 = net.addLink(hX, sL3)   # host ngoài vào L3

    net.start()
    info('*** Configuring VLAN access on ports\n')

    # Tên cổng phía switch cho từng link
    # (intf1 là node thứ nhất trong addLink(); intf2 là node thứ hai)
    p_s1_h1   = l_h1_s1.intf2.name
    p_s1_h2   = l_h2_s1.intf2.name
    p_s1_up   = l_s1_sL3.intf1.name   # cổng uplink ở s1

    p_s2_h3   = l_h3_s2.intf2.name
    p_s2_h4   = l_h4_s2.intf2.name
    p_s2_up   = l_s2_sL3.intf1.name   # cổng uplink ở s2

    p_sL3_to_s1 = l_s1_sL3.intf2.name
    p_sL3_to_s2 = l_s2_sL3.intf2.name
    p_sL3_to_hX = l_hX_sL3.intf2.name

    # Gán VLAN access cho toàn bộ port trong mỗi VLAN
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

    # External = VLAN 200 (access ở phía sL3; hX là host thường)
    sL3.cmd(f'ovs-vsctl set port {p_sL3_to_hX} tag=200')

    info('*** Tạo SVI (internal ports) trên sL3 và gán IP\n')
    # VLAN 101
    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan101 tag=101 -- set interface sL3-vlan101 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan101')
    sL3.cmd('ip addr add 10.0.1.1/24 dev sL3-vlan101')
    sL3.cmd('ip link set sL3-vlan101 up')

    # VLAN 102
    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan102 tag=102 -- set interface sL3-vlan102 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan102')
    sL3.cmd('ip addr add 10.0.2.1/24 dev sL3-vlan102')
    sL3.cmd('ip link set sL3-vlan102 up')

    # VLAN 200
    sL3.cmd('ovs-vsctl --may-exist add-port sL3 sL3-vlan200 tag=200 -- set interface sL3-vlan200 type=internal')
    sL3.cmd('ip addr flush dev sL3-vlan200')
    sL3.cmd('ip addr add 192.168.10.1/24 dev sL3-vlan200')
    sL3.cmd('ip link set sL3-vlan200 up')

    info('*** Bật IP forwarding (L3 routing)\n')
    sL3.cmd('sysctl -w net.ipv4.ip_forward=1')

    info('*** Kiểm tra nhanh kết nối liên mạng\n')
    # Dept1 <-> Dept2
    net.ping([h1, h3])
    # Dept1 <-> External
    net.ping([h2, hX])

    info('*** Mở CLI để bạn test thêm\n')
    CLI(net)

    info('*** Dừng mạng và dọn dẹp SVI\n')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan101')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan102')
    sL3.cmd('ovs-vsctl del-port sL3 sL3-vlan200')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

