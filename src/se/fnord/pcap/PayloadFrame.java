package se.fnord.pcap;

import java.nio.ByteBuffer;

public interface PayloadFrame extends PacketFrame {
	int capturedLength();

	int originalLength();

	int subProtocol();

	ByteBuffer payload();
}