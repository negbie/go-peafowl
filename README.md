<img src="https://i.imgur.com/jrQX0Of.gif" width=250> 

# go-peafowl

### About

[Peafowl](https://github.com/DanieleDeSensi/Peafowl) is a flexible and extensible DPI framework which can be used to identify the application protocols carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols. This module allows golang projects to leverage the power of Peafowl for Deep-Packet Inspection of live and recorded network traffic.


#### Usage Example
```
make
./go-peafowl -rf pcap/http.pcap
```


#### Credits & Acknowledgements
All wrapped C functions at top of main.go are from [M. Campus](https://github.com/kYroL01)

Check out [node-peafowl](https://github.com/lmangani/node-peafowl) by [L. Mangani](https://github.com/lmangani), [M. Campus](https://github.com/kYroL01)
