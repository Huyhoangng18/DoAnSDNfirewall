phần này có 2 mô hình mạng mininet:

1 là mohinhmininet.py là mô hình không có can thệp của Controller Ryu

2 là mohinhnet.py có can thiệp của Controller Ryu với các rules cơ bản

để chạy mô hình 1:
1. Cần cài mininet
2. Khởi động mô hình mạng miniet: sudo python3 mohinhmininet.py

để chạy mô hình 2:
1. Cần cài Ryu, mininet
2. Khởi động controller Ryu bằng câu lệnh: sudo ryu-manager --observe-links rulesbase.py
3. Khởi động mô hình mạng miniet: sudo python3 mohinhnet.py
