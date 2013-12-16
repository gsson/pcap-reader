package se.fnord.pcap;

import java.nio.ByteBuffer;
import java.util.Set;

public class TcpFrame implements PayloadFrame {
	public enum TcpFlag implements Flag {
		NS(8), CWR(7), ECE(6), URG(5), ACK(4), PSH(3), RST(2), SYN(1), FIN(0);

		private final int index;

		private TcpFlag(int index) {
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
	private final int headerSize;
	private final int srcPort;
	private final int dstPort;
	private final ByteBuffer payload;
	private final Set<TcpFlag> flags;
	private final int windowSize;
	private final int urgentPointer;
	private final long sequence;
	private final long ackNumber;

	public TcpFrame(PayloadFrame parent, int headerSize, int srcPort, int dstPort, long sequence, long ackNumber,
	    Set<TcpFlag> flags, int windowSize, int urgent, ByteBuffer payload) {
		this.parent = parent;
		this.headerSize = headerSize;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.sequence = sequence;
		this.ackNumber = ackNumber;
		this.flags = flags;
		this.windowSize = windowSize;
		this.urgentPointer = urgent;
		this.payload = payload;
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

	public int srcPort() {
		return srcPort;
	}

	public int dstPort() {
		return dstPort;
	}

	public Set<TcpFlag> flags() {
		return flags;
	}

	public int windowSize() {
		return windowSize;
	}

	public int urgentPointer() {
		return urgentPointer;
	}

	public long ackNumber() {
		return ackNumber;
	}

	public long sequence() {
		return sequence;
	}

	@Override
	public int subProtocol() {
		return -1;
	}
}
