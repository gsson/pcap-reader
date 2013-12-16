package se.fnord.pcap.decoder;

import java.nio.ByteBuffer;
import java.util.Set;

import se.fnord.pcap.Flag;
import se.fnord.pcap.PayloadFrame;
import se.fnord.pcap.PcapRecord;

public class Ipv4Frame implements PayloadFrame {
	public enum Ipv4Flag implements Flag {
		MF(1), DF(2);

		private final int index;

		private Ipv4Flag(int index) {
			this.index = index;
		}

		public int index() {
			return index;
		}

		public int bit() {
			return 1 << index;
		}
	}

	private final PayloadFrame parent;
	private final int dstIp;
	private final int srcIp;
	private final short fragmentId;
	private final int fragmentOffset;
	private final int ttl;
	private final int protocol;
	private final ByteBuffer payload;
	private final int headerSize;
	private Set<Ipv4Flag> flags;

	public Ipv4Frame(PayloadFrame parent, int headerSize, short id, Set<Ipv4Flag> flags, int fragmentOffset, int ttl,
	    int protocol, int srcIp, int dstIp, ByteBuffer payload) {
		this.parent = parent;
		this.headerSize = headerSize;
		this.fragmentId = id;
		this.flags = flags;
		this.fragmentOffset = fragmentOffset;
		this.ttl = ttl;
		this.protocol = protocol;
		this.srcIp = srcIp;
		this.dstIp = dstIp;
		this.payload = payload;
	}

	public short fragmentId() {
		return fragmentId;
	}

	public int fragmentOffset() {
		return fragmentOffset;
	}

	public Set<Ipv4Flag> flags() {
		return flags;
	}

	private int headerSize() {
		return headerSize;
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

	public int protocol() {
		return protocol;
	}

	public int dstIp() {
		return dstIp;
	}

	public int srcIp() {
		return srcIp;
	}

	public int ttl() {
		return ttl;
	}

	@Override
	public int subProtocol() {
		return protocol();
	}
}
