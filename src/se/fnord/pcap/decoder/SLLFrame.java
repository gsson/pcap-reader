package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;

import se.fnord.pcap.PayloadFrame;
import se.fnord.pcap.PcapRecord;

public class SLLFrame implements PayloadFrame {
	private final PayloadFrame parent;
	private final short packetType;
	private final short etherType;
	private final byte[] address;
	private final ByteBuffer payload;
	private final short protocol;

	public SLLFrame(PayloadFrame parent, short packetType, short etherType, byte[] address, short protocol,
	    ByteBuffer payload) {
		this.parent = parent;
		this.packetType = packetType;
		this.etherType = etherType;
		this.address = address;
		this.protocol = protocol;
		this.payload = payload;
	}

	private int headerSize() {
		return 16;
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

	public short etherType() {
		return etherType;
	}

	public short protocol() {
		return protocol;
	}

	public byte[] address() {
		return address.clone();
	}

	public short packetType() {
		return packetType;
	}

	@Override
	public int subProtocol() {
		return protocol();
	}
}
