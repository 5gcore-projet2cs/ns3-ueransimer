# mmWave ns3-ueransimer module #

This is an [ns-3](https://www.nsnam.org "ns-3 Website") module for the simulation
of 5G cellular networks operating at mmWaves. A description of this module can be found in [this paper](https://ieeexplore.ieee.org/document/8344116/ "mmwave paper").

Make sure that the free5gc and the ueransim containers are running,

## Usage Examples

To connect to the UERANSIM container use this command, run:
```sh
sudo ./ns3 connect 10.100.200.13 #10.100.200.13 is the ip address of the ueransim container
```

To run a simulation with custom parameters:
```sh
./ns3 run scratch/ue.cpp -h 8.8.8.8 -c 10 -o captured -lpcap -lxlsxwriter # send 10 packets to 8.8.8.8 throught the gNb of ueransim that forwards packets to free5gc and output the trace in files named captured that has many extensions 'xls, json, pcap...'
```
