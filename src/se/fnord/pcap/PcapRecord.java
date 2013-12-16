package se.fnord.pcap;


public interface PcapRecord extends PayloadFrame {
	long timestamp();

	int index();
}