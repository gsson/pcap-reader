package se.fnord.pcap;

import java.util.ArrayDeque;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Queue;
import java.util.Set;

import se.fnord.pcap.TcpFrame.TcpFlag;
import se.fnord.pcap.TcpSessionEvent.Direction;
import se.fnord.pcap.decoder.Ipv4Frame;

public class TcpAssembler implements IteratorFactory<TcpFrame, TcpSessionEvent> {

	private enum State {
		CLOSED, OPEN;
	}

	private static class TcpSessionKey {
		private final Direction direction;
		private final TcpSessionId id;

		public TcpSessionKey(Direction direction, TcpSessionId id) {
			this.direction = direction;
			this.id = id;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (!(obj instanceof TcpSessionKey))
				return false;
			TcpSessionKey other = (TcpSessionKey) obj;
			return this.direction == other.direction && this.id.equals(other.id);
		}

		@Override
		public int hashCode() {
			return direction.hashCode() * 31 + id.hashCode();
		}

		public TcpSessionKey reverse() {
			return new TcpSessionKey(direction.reverse(), id);
		}

		@Override
		public String toString() {
			return String.format("%s/%s", id, direction);
		}
	}



	private static TcpSessionKey fromServer(Ipv4Frame ip, TcpFrame tcp) {
		return new TcpSessionKey(Direction.FROM_SERVER, new TcpSessionId(ip.dstIp(), tcp.dstPort(), ip.srcIp(), tcp.srcPort()));
	}

	private static TcpSessionKey fromClient(Ipv4Frame ip, TcpFrame tcp) {
		return new TcpSessionKey(Direction.FROM_CLIENT, new TcpSessionId(ip.srcIp(), tcp.srcPort(), ip.dstIp(), tcp.dstPort()));
	}

	private static final Set<TcpFlag> SYN = TcpDecoder.flags(TcpFlag.SYN);
	private static final Set<TcpFlag> SYN_ACK = TcpDecoder.flags(TcpFlag.SYN, TcpFlag.ACK);

	private static TcpSessionKey guessDirection(Ipv4Frame ip, TcpFrame tcp) {
		if (SYN.equals(tcp.flags()))
			return fromClient(ip, tcp);
		if (SYN_ACK.equals(tcp.flags()))
			return fromServer(ip, tcp);
		if (tcp.srcPort() > tcp.dstPort())
			return fromClient(ip, tcp);
		return fromServer(ip, tcp);
	}

	private class EventIterator implements Iterator<TcpSessionEvent> {
		private class TcpSession {
			private class Sequence {
				public long ack = -1;
				public long seq = -1;
				public long nextSeq = -1;
				public Direction direction;

				public Sequence(Direction direction) {
					this.direction = direction;
				}

				public void syn(TcpFrame tcp) {
					if (this.seq != -1)
						end(tcp.rootFrame().index(), direction, true);
					start(tcp.rootFrame().index(), direction);
					this.seq = tcp.sequence();
					this.nextSeq = seq + 1;
				}

				public void fin(TcpFrame tcp) {
					this.seq = -1;
					this.nextSeq = -1;
					this.ack = -1;
					end(tcp.rootFrame().index(), direction, false);
				}

				public boolean ack(long ack) {
					if (ack <= this.ack) {
						// Duplicate ack; ignore
						return false;
					}
					this.ack = ack;
					return true;
				}

				private long wrap(long s, int l) {
					return (s + l) & 0xffffffff;
				}

				public void seq(TcpFrame tcp) {
					long s = tcp.sequence();
					int l = tcp.originalLength();
					if (seq == s && nextSeq == wrap(s, l)) {
						// Duplicate
						return;
					}

					if (seq != -1 && nextSeq != s) {
						// System.err.printf("Missing %d bytes in stream between %d and %d\n", s - nextSeq, seq, s);
						missing(tcp.rootFrame().index(), direction, (int) (s - nextSeq));
					}

					seq = s;
					nextSeq = wrap(s, l);

					if (l > 0)
						data(direction, tcp);
				}

				@Override
				public String toString() {
					return String.format("[seq: %d, len: %d, ack: %d]", seq, nextSeq - seq, ack);
				}
			}

			private final TcpSessionId sessionKey;
			private State state = State.CLOSED;
			private Sequence server = new Sequence(Direction.FROM_SERVER);
			private Sequence client = new Sequence(Direction.FROM_CLIENT);
			private EnumSet<Direction> openDirection = EnumSet.noneOf(Direction.class);

			private void start(int index, Direction direction) {
				if (openDirection.isEmpty()) {
					state = State.OPEN;
					pending.add(new TcpSessionStart(sessionKey, index));
				}
				openDirection.add(direction);
			}

			private void end(int index, Direction direction, boolean force) {
				if (force)
					openDirection.clear();
				else
					openDirection.remove(direction);

				if (state != State.CLOSED && openDirection.isEmpty()) {
					pending.add(new TcpSessionEnd(sessionKey, index));
					state = State.CLOSED;
				}
			}

			private void data(Direction direction, TcpFrame tcp) {
				pending.add(new TcpSessionData(tcp, sessionKey, direction));
			}

			private void missing(int index, Direction direction, int length) {
				if (state == State.CLOSED)
					throw new IllegalStateException();
				pending.add(new TcpSessionMissingData(sessionKey, direction, index, length));
			}

			public TcpSession(TcpSessionId key) {
				this.sessionKey = key;
			}

			private Sequence sequenceFor(Direction direction) {
				return direction == Direction.FROM_CLIENT ? client : server;
			}

			private void handle(Direction direction, TcpFrame tcp) {
				Sequence s = sequenceFor(direction);
				if (tcp.flags().contains(TcpFlag.SYN))
					s.syn(tcp);
				else
					s.seq(tcp);

				if (tcp.flags().contains(TcpFlag.FIN) || tcp.flags().contains(TcpFlag.RST))
					s.fin(tcp);

				if (tcp.flags().contains(TcpFlag.ACK)) {
					Sequence r = sequenceFor(direction.reverse());
					r.ack(tcp.ackNumber());
				}
			}

			@Override
			public String toString() {
				return String.format("%s: %s %s", sessionKey, server, client);
			}
		}

		private final Map<TcpSessionKey, TcpSession> sessions = new HashMap<>();
		private final Queue<TcpSessionEvent> pending = new ArrayDeque<>();
		private final Iterator<TcpFrame> iterator;
		private TcpSessionEvent next = null;

		public EventIterator(Iterator<TcpFrame> iterator) {
			this.iterator = iterator;
		}

		private TcpSession getSession(TcpSessionKey key, TcpFrame tcp) {
			TcpSession session;
			session = sessions.get(key);
			if (session == null) {
				session = sessions.get(key.reverse());
				if (session == null) {
					session = new TcpSession(key.id);
				}

				if (!tcp.flags().contains(TcpFlag.FIN) && !tcp.flags().contains(TcpFlag.RST)) {
					sessions.put(key, session);
				}
			}
			return session;
		}

		private void removeSession(TcpSessionKey key) {
			sessions.remove(key);
		}

		public void assemble(TcpFrame tcp) {
			Ipv4Frame ip = (Ipv4Frame) tcp.parentFrame();
			TcpSessionKey key = guessDirection(ip, tcp);
			TcpSession session = getSession(key, tcp);

			session.handle(key.direction, tcp);

			if (tcp.flags().contains(TcpFlag.FIN) || tcp.flags().contains(TcpFlag.RST)) {
				removeSession(key);
			}
		}


		@Override
        public boolean hasNext() {
			if (next != null)
				return true;
			next = pending.poll();
			if (next != null)
				return true;
			while (iterator.hasNext() && next == null) {
				assemble(iterator.next());
				next = pending.poll();
			}
			return next != null;
        }

		@Override
		public TcpSessionEvent next() {
			if (!hasNext())
				throw new NoSuchElementException();
			TcpSessionEvent n = next;
			next = null;
			return n;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}


	@Override
	public Iterator<TcpSessionEvent> map(Iterator<TcpFrame> from) {
		return new EventIterator(from);
	}
}

