package se.fnord.pcap;

import se.fnord.pcap.internal.Util;

public class TcpSessionMissingData implements TcpSessionEvent {
	private final int length;
	private final TcpSessionId key;
	private final Direction direction;
	private final int index;

	public TcpSessionMissingData(TcpSessionId key, Direction direction, int index, int length) {
		this.key = key;
		this.direction = direction;
		this.index = index;
		this.length = length;
	}

	@Override
	public TcpSessionId session() {
		return key;
	}

	@Override
	public Direction direction() {
		return direction;
	}

	public int capturedLength() {
		return 0;
	}

	public int originalLength() {
		return length;
	}

	@Override
	public String toString() {
		if (direction == Direction.FROM_CLIENT) {
			return String.format("<session data missing %s:%d->%s:%d: %d bytes>", Util.toDottedQuad(key.clientAddress()),
			    key.clientPort(), Util.toDottedQuad(key.serverAddress()), key.serverPort(), length);
		}
		return String.format("<session data missing %s:%d->%s:%d: %d bytes>", Util.toDottedQuad(key.serverAddress()),
		    key.serverPort(), Util.toDottedQuad(key.clientAddress()), key.clientPort(), length);
	}

	@Override
	public int index() {
		return index;
	}
}
