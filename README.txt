Usage:
perl log_parser.pl -f ../../routerHack.txt

Sample input file....
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[DoS Attack: SYN/ACK Scan] from source: 210.242.73.33, port 80, Saturday, April 01, 2017 22:12:34
[DoS Attack: SYN/ACK Scan] from source: 216.239.38.21, port 80, Saturday, April 01, 2017 22:12:26
[DoS Attack: SYN/ACK Scan] from source: 216.239.38.21, port 80, Saturday, April 01, 2017 22:07:58
[DoS Attack: SYN/ACK Scan] from source: 216.239.38.21, port 80, Saturday, April 01, 2017 22:06:12
[DoS Attack: SYN/ACK Scan] from source: 216.239.38.21, port 80, Saturday, April 01, 2017 21:48:29
[DoS Attack: SYN/ACK Scan] from source: 69.195.124.104, port 80, Saturday, April 01, 2017 21:44:36
[DoS Attack: SYN/ACK Scan] from source: 216.239.36.21, port 80, Saturday, April 01, 2017 21:42:18
[DoS Attack: TCP/UDP Chargen] from source: 184.105.139.89, port 24584, Saturday, April 01, 2017 21:41:09


Sample output of the log parser....
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
RST Scan Hits from IP:Port...(14 hosts)
---------------------------------------
  1) 80.179.94.25:80 = 1
  2) 209.222.104.48:25565 = 1
  3) 64.124.217.61:443 = 1

SYN/ACK Scan Hits from IP:Port...(101 hosts)
---------------------------------------
  1) 144.0.1.119:9008 = 1
  2) 164.132.205.139:25565 = 1
  3) 52.86.40.75:5222 = 2
  4) 119.6.229.38:80 = 1
  5) 176.9.0.137:80 = 1
  6) 193.70.46.106:22 = 6
  7) 193.70.46.106:20100 = 14
  
ACK Scan Hits from IP:Port...(36 hosts)
---------------------------------------
  1) 104.244.46.167:443 = 1
  2) 31.13.74.1:443 = 3
  3) 52.71.116.237:443 = 4
  4) 59.127.102.177:18202 = 1
  5) 104.244.46.135:443 = 6
  
  TCP/UDP Chargen Hits from IP:Port...(14 hosts)
---------------------------------------
  1) 184.105.139.77:60524 = 1
  2) 185.94.111.1:34239 = 1
  3) 185.94.111.1:58343 = 1
  4) 185.94.111.1:38474 = 1
  5) 185.94.111.1:60790 = 1
