Cách khởi động API_ryu
1. Cần cài Ryu, mininet, Suricata và cấu hình theo hướng đẫn phụ lục đồ án
2. Khởi động controller Ryu bằng câu lệnh:
   sudo ryu-manager --observe-links unified_sdn.py
4. Khởi động mô hình mạng miniet:
   sudo python3 mohinhnet_final.py
5. Khởi động api gateway để vào giao diện truy cập qua http://127.0.0.1:5000:
   python3 api_gateway.py
6. Khởi động lại suricata cho IDS:
   sudo systemctl restart suricata
