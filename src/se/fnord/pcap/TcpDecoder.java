package se.fnord.pcap;

import java.nio.ByteBuffer;
import java.util.Set;

import se.fnord.pcap.TcpFrame.TcpFlag;
import se.fnord.pcap.internal.AbstractFlagSet;

public class TcpDecoder<FROM extends PayloadFrame> implements DecoderFunction<FROM, TcpFrame> {
	private static class TcpFlags extends AbstractFlagSet<TcpFlag> {
		private static final TcpFlag[] BY_INDEX = AbstractFlagSet.createIndex(TcpFlag.class);
		private static final int flagMask = AbstractFlagSet.createMask(TcpFlag.class);

		private TcpFlags(int flags) {
			super(flags & flagMask, TcpFlag.class, BY_INDEX);
		}
	}

	public static Set<TcpFlag> flags(TcpFlag... flags) {
		int n = 0;
		for (TcpFlag flag : flags)
			n |= flag.bit();
		return new TcpFlags(n);
	}

	public TcpFrame decode(FROM from) {
		ByteBuffer payload = from.payload();
		int start = payload.position();

		int srcPort = payload.getShort() & 0xffff;
		int dstPort = payload.getShort() & 0xffff;
		long sequence = payload.getInt() & 0xffffffffl;
		long ackNumber = payload.getInt() & 0xffffffffl;
		int x = payload.getShort() & 0xffff;
		int headerLength = x >>> 12;
		TcpFlags flags = new TcpFlags(x & 0xfff);
		int windowSize = payload.getShort();
		/*int checksum = */payload.getShort();
		int urgent = payload.getShort();

		payload.position(start + headerLength * 4);
		return new TcpFrame(from, headerLength * 4, srcPort, dstPort, sequence, ackNumber, flags, windowSize, urgent,
		    payload.slice());
	}
}
