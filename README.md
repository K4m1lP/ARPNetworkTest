# ARPNetworkTest

Simple program to perform DoS attack while DAD. For every ARP Probe sent in network, this program is responding, telling that IP address is already in use. Raw sockets was used to achieve that goal. 

Usage:
Program is using linux raw socket. 
Program require to pass the name of network interface, which you can check with: 


``` 
$ip link show 
```

Design for educational purposes only.
