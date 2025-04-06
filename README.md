# PCAP Packet Sniffer (TCP 전용)

이 프로젝트는 `libpcap` 라이브러리를 사용하여 네트워크 상의 TCP 패킷을 캡처하고,  
Ethernet / IP / TCP 헤더 정보를 추출하여 출력하는 간단한 스니퍼 프로그램입니다.

---

## 📌 기능

- Ethernet Header: 출발지 MAC / 목적지 MAC 출력
- IP Header: 출발지 IP / 목적지 IP 출력
- TCP Header: 출발지 포트 / 목적지 포트 출력
- Message(payload): 최대 16바이트 출력
- TCP 프로토콜만 캡처 (UDP 무시)

---

## 🛠 사용 방법
1. 컴파일
gcc -o sniffer sniffer.c -lpcap

2. 실행 (root 권한 필요)
sudo ./sniffer
※ 네트워크 인터페이스가 enp0s3이 아닌 경우, 코드에서 인터페이스 이름 수정 필요
