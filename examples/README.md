# Example PCAP Files

Place sample PCAP/PCAPNG files here for testing Beacon.

## Where to Get Sample PCAPs

**Public Capture Repositories:**
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://malware-traffic-analysis.net/)
- [NETRESEC Public PCAP Files](https://www.netresec.com/index.ashx?page=PcapFiles)

**Generate Your Own:**
```bash
# Capture on network interface
tcpdump -i eth0 -w capture.pcap

# Or use TShark
tshark -i eth0 -w capture.pcapng
```

## Example Usage

```bash
# Analyze example capture
python -m beacon analyze examples/sample.pcapng

# Quick info
python -m beacon info examples/sample.pcapng
```
