package se.fnord.pcap;

import java.nio.ByteBuffer;

public class UdpFrame implements PayloadFrame {
	private final PayloadFrame parent;
	private final int srcPort;
	private final int dstPort;
	private final ByteBuffer payload;

	public UdpFrame(PayloadFrame parent, int srcPort, int dstPort, ByteBuffer payload) {
		this.parent = parent;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.payload = payload;
	}

	private int headerSize() {
		return 8;
	}

	@Override
	public PcapRecord rootFrame() {
		return parent.rootFrame();
	}

	@Override
	public PayloadFrame parentFrame() {
	    return parent;
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

	public int srcPort() {
		return srcPort;
	}

	public int dstPort() {
		return dstPort;
	}

	@Override
	public int subProtocol() {
		return -1;
	}
}
