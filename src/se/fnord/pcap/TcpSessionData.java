package se.fnord.pcap;

import java.nio.ByteBuffer;

import se.fnord.pcap.internal.Util;

public class TcpSessionData implements PayloadFrame, TcpSessionEvent {
	private final PayloadFrame parent;
	private final TcpSessionId key;
	private final Direction direction;

	public TcpSessionData(PayloadFrame parent, TcpSessionId key, Direction direction) {
		this.parent = parent;
		this.key = key;
		this.direction = direction;
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
		return parent.capturedLength();
	}

	@Override
	public int originalLength() {
		return parent.originalLength();
	}

	@Override
	public ByteBuffer payload() {
		return parent.payload();
	}

	@Override
	public int subProtocol() {
		return -1;
	}

	@Override
	public TcpSessionId session() {
		return key;
	}

	@Override
	public Direction direction() {
		return direction;
	}

	@Override
	public String toString() {
		if (direction == Direction.FROM_CLIENT) {
			return String.format("<session data %s:%d->%s:%d: %d bytes>", Util.toDottedQuad(key.clientAddress()), key.clientPort(),
			    Util.toDottedQuad(key.serverAddress()), key.serverPort(), parent.originalLength());
		}
		return String.format("<session data %s:%d->%s:%d: %d bytes>", Util.toDottedQuad(key.serverAddress()), key.serverPort(),
		    Util.toDottedQuad(key.clientAddress()), key.clientPort(), parent.originalLength());

	}

	@Override
	public int index() {
		return rootFrame().index();
	}
}
