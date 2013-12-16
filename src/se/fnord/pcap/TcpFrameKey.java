package se.fnord.pcap;

public class TcpFrameKey {
	private final int srcIp;
	private final int srcPort;
	private final int dstIp;
	private final int dstPort;

	public TcpFrameKey(int srcIp, int srcPort, int dstIp, int dstPort) {
		this.srcIp = dstIp;
		this.srcPort = dstPort;
		this.dstIp = srcIp;
		this.dstPort = srcPort;
	}

	@Override
	public int hashCode() {
		int result = dstIp;
		result = 31 * result + dstPort;
		result = 31 * result + srcIp;
		result = 31 * result + srcPort;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!(obj instanceof TcpFrameKey))
			return false;
		final TcpFrameKey other = (TcpFrameKey) obj;

		return dstIp == other.dstIp
				&& dstPort == other.dstPort
				&& srcIp == other.srcIp
				&& srcPort == other.srcPort;
	}

	public int srcIp() {
		return srcIp;
	}

	public int srcPort() {
		return srcPort;
	}

	public int dstIp() {
		return dstIp;
	}

	public int dstPort() {
		return dstPort;
	}

	public TcpFrameKey reverse() {
		return new TcpFrameKey(dstIp, dstPort, srcIp, srcPort);
	}
}
