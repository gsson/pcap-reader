package se.fnord.pcap;

import se.fnord.pcap.internal.Util;

public class TcpSessionEnd implements TcpSessionEvent {
	private final TcpSessionId key;
	private final int index;

	public TcpSessionEnd(TcpSessionId key, int index) {
		this.key = key;
		this.index = index;
	}

	@Override
	public TcpSessionId session() {
		return key;
	}

	@Override
	public Direction direction() {
		return Direction.NONE;
	}

	@Override
	public String toString() {
		return String.format("<session end %s:%d->%s:%d>", Util.toDottedQuad(key.clientAddress()), key.clientPort(),
		    Util.toDottedQuad(key.serverAddress()), key.serverPort());
	}

	@Override
	public int index() {
		return index;
	}
}
