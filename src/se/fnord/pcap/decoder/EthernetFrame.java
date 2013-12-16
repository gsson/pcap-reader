package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;

import se.fnord.pcap.PayloadFrame;
import se.fnord.pcap.PcapRecord;

public class EthernetFrame implements PayloadFrame {
	private final PayloadFrame parent;
	private final long dstMac;
	private final long srcMac;
	private final int[] vlanTags;
	private final short etherType;
	private final ByteBuffer payload;

	public EthernetFrame(PayloadFrame parent, long dstMac, long srcMac, int[] vlanTags, short etherType, ByteBuffer payload) {
		this.parent = parent;
		this.dstMac = dstMac;
		this.srcMac = srcMac;
		this.vlanTags = vlanTags;
		this.etherType = etherType;
		this.payload = payload;
	}

	private int headerSize() {
		return 6 + 6 + vlanTags.length * 4 + 2;
	}

	@Override
	public PcapRecord rootFrame() {
		return parent.rootFrame();
	}

	@Override
	public PayloadFrame parentFrame() {
	    return parent;
    }

	public int[] vlanTags() {
		return vlanTags;
	}

	@Override
	public int capturedLength() {
		return parent.capturedLength() - headerSize();
	}

	@Override
	public int originalLength() {
		return parent.originalLength() - headerSize();
	}

	@Override
	public ByteBuffer payload() {
		return payload.slice();
	}

	public short etherType() {
		return etherType;
	}

	public long dstMac() {
		return dstMac;
	}

	public long srcMac() {
		return srcMac;
	}

	@Override
	public int subProtocol() {
		return etherType();
	}
}
