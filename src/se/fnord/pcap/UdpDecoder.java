package se.fnord.pcap;

import java.nio.ByteBuffer;

public class UdpDecoder<FROM extends PayloadFrame> implements DecoderFunction<FROM, UdpFrame> {
	public UdpFrame decode(FROM from) {
		ByteBuffer payload = from.payload();
		int start = payload.position();

		int srcPort = payload.getShort() & 0xffff;
		int dstPort = payload.getShort() & 0xffff;
		//int length = payload.getShort() & 0xffff;
		//int checksum = payload.getShort() & 0xffff;

		payload.position(start + 8);
		return new UdpFrame(from, srcPort, dstPort, payload.slice());
	}
}
