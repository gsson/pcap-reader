package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;

import se.fnord.pcap.DecoderFunction;
import se.fnord.pcap.PayloadFrame;

public class SLLDecoder<FROM extends PayloadFrame> implements DecoderFunction<FROM, SLLFrame> {
	@Override
	public SLLFrame decode(FROM from) {
		ByteBuffer payload = from.payload();
		short packetType = payload.getShort();
		short etherType = payload.getShort();
		short addressLength = payload.getShort();
		byte[] address = new byte[addressLength];
		payload.get(address);
		payload.position(payload.position() + 8 - addressLength);
		short protocol = payload.getShort();
		return new SLLFrame(from, packetType, etherType, address, protocol, payload.slice());

	}
}
