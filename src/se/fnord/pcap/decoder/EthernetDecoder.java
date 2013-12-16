package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;
import java.util.Arrays;

import se.fnord.pcap.DecoderFunction;
import se.fnord.pcap.PayloadFrame;

public class EthernetDecoder<FROM extends PayloadFrame> implements DecoderFunction<FROM, EthernetFrame> {
	private static final int[] NO_VLAN = new int[0];
	private final int[] vlanScratch = new int[64];

	private static long getMac(ByteBuffer bb) {
		long mac = bb.getShort() & 0xffffL;
		return (mac << 32) | (bb.getInt() & 0xffffffffL);
	}

	@Override
	public EthernetFrame decode(FROM from) {
		ByteBuffer payload = from.payload();

		long dstMac = getMac(payload);
		long srcMac = getMac(payload);
		int tpid = payload.getShort() & 0xffff;
		int[] vlans = NO_VLAN;
		int tagCount = 0;
		if (tpid == 0x8100 || tpid == 0x88a8 || tpid == 0x9100) {
			vlanScratch[tagCount++] = (tpid << 16) | (payload.getShort() & 0xffff);
			tpid = payload.getShort() & 0xffff;
			while (tpid == 0x8100 || tpid == 0x88a8 || tpid == 0x9100) {
				vlanScratch[tagCount++] = (tpid << 16) | (payload.getShort() & 0xffff);
				tpid = payload.getShort() & 0xffff;
			}
			vlans = Arrays.copyOf(vlanScratch, tagCount);
		}
		short etherType = (short) tpid;
		return new EthernetFrame(from, dstMac, srcMac, vlans, etherType, payload.slice());
	}
}
