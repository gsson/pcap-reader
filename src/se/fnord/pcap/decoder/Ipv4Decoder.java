package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;

import se.fnord.pcap.DecoderFunction;
import se.fnord.pcap.PayloadFrame;
import se.fnord.pcap.decoder.Ipv4Frame.Ipv4Flag;
import se.fnord.pcap.internal.AbstractFlagSet;

public class Ipv4Decoder<FROM extends PayloadFrame> implements DecoderFunction<FROM, Ipv4Frame> {
	private static class Ipv4Flags extends AbstractFlagSet<Ipv4Flag> {
		private static final Ipv4Flag[] BY_INDEX = AbstractFlagSet.createIndex(Ipv4Flag.class);
		private static final int flagMask = AbstractFlagSet.createMask(Ipv4Flag.class);

		private Ipv4Flags(int flags) {
			super(flags & flagMask, Ipv4Flag.class, BY_INDEX);
		}
	}

	public Ipv4Frame decode(FROM from) {
		ByteBuffer payload = from.payload();
		int start = payload.position();

		byte b = payload.get();
		//int version = b >>> 4;
		int headerLength = (b & 0x0f);
		payload.get(); // TOS / DiffServ
		payload.getShort(); // Total Length

		short fragId = payload.getShort();
		short fragInfo = payload.getShort();
		Ipv4Flags flags = new Ipv4Flags(fragInfo & 3);
		int fragOffset = fragInfo >>> 3;

		int ttl = payload.get() & 0xff;
		int protocol = payload.get() & 0xff;
		payload.getShort();

		int srcIp = payload.getInt();

		int dstIp = payload.getInt();

		payload.position(start + headerLength * 4);
		return new Ipv4Frame(from, headerLength * 4, fragId, flags, fragOffset, ttl, protocol, srcIp, dstIp, payload.slice());
	}
}
