package se.fnord.pcap;

public interface PacketFrame {
	PayloadFrame parentFrame();

	PcapRecord rootFrame();
}