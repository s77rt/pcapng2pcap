## pcapng2pcap
convert pcapng capture file to pcap

### Features
- Convert simple pcapng to pcap
- Convert simple gzipped pcapng to pcap
- Convert complex* pcapng to pcap
- Convert complex* gzipped pcapng to pcap

\*contains multiple section header blocks

### Building
```
git clone https://github.com/s77rt/pcapng2pcap.git
cd pcapng2pcap
make
make install
```

### Usage
`pcapng2pcap <INPUT_FILENAME> <OUTPUT_PREFIX>`

### Example
`pcapng2pcap mycapture.pcapng mycapture`

Will produce mycapture.1.pcap, mycapture.2.pcap, ... , mycapture.n.pcap

Where n is the number of section header blocks in mycapture.pcapng

### Changelog
Refer to [CHANGELOG.md](https://github.com/s77rt/pcapng2pcap/blob/master/docs/CHANGELOG.md)

### Limits
Refer to [limits.txt](https://github.com/s77rt/pcapng2pcap/blob/master/docs/limits.txt)
