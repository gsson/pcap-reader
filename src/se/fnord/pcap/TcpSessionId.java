package se.fnord.pcap;

public class TcpSessionId {
	private final int serverIp;
	private final int serverPort;
	private final int clientIp;
	private final int clientPort;

	public TcpSessionId(int clientIp, int clientPort, int serverIp, int serverPort) {
		this.serverIp = serverIp;
		this.serverPort = serverPort;
		this.clientIp = clientIp;
		this.clientPort = clientPort;
	}

	@Override
	public int hashCode() {
		int result = clientIp;
		result = 31 * result + clientPort;
		result = 31 * result + serverIp;
		result = 31 * result + serverPort;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!(obj instanceof TcpSessionId))
			return false;
		final TcpSessionId other = (TcpSessionId) obj;

		return clientIp == other.clientIp && clientPort == other.clientPort && serverIp == other.serverIp &&
		    serverPort == other.serverPort;
	}

	private String ipToString(int ip) {
		return String.format("%d.%d.%d.%d", ip >>> 24, (ip >>> 16) & 0xff, (ip >>> 8) & 0xff, ip & 0xff);
	}

	@Override
	public String toString() {
		return String.format("%s:%d <-> %s:%d", ipToString(clientIp), clientPort, ipToString(serverIp), serverPort);
	}

	public int clientAddress() {
		return clientIp;
	}

	public int clientPort() {
		return clientPort;
	}

	public int serverAddress() {
		return serverIp;
	}

	public int serverPort() {
		return serverPort;
	}
}
