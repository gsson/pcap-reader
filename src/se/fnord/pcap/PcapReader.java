package se.fnord.pcap;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

public class PcapReader implements Iterable<PcapRecord> {
	private interface StructReader<T> {
		int size();

		T deserialize(ByteBuffer bb);
	}

	public static class GlobalHeaderReader implements StructReader<GlobalHeader> {
		@Override
		public int size() {
			return 24;
		}

		@Override
		public GlobalHeader deserialize(ByteBuffer bb) {
			ByteOrder order = bb.order();
			bb.order(ByteOrder.BIG_ENDIAN);

			int byteOrder = bb.getInt(0);
			ByteOrder fileOrder = (byteOrder & 0xffff0000) == 0xa1b20000 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			bb.order(fileOrder);

			int magic_number = bb.getInt();
			short version_major = bb.getShort();
			short version_minor = bb.getShort();
			int thiszone = bb.getInt();
			int sigfigs = bb.getInt();
			int snaplen = bb.getInt();
			int network = bb.getInt();

			TimeUnit resolution = (magic_number & 0x0000ffff) == 0x0000c3d4 ? TimeUnit.MICROSECONDS : TimeUnit.NANOSECONDS;
			bb.order(order);
			return new GlobalHeader(magic_number, fileOrder, resolution, version_major, version_minor, thiszone, sigfigs, snaplen,
			    network);
		}
	}

	public static class RecordHeaderReader implements StructReader<RecordHeader> {
		@Override
		public int size() {
			return 16;
		}

		@Override
		public RecordHeader deserialize(ByteBuffer bb) {
			long ts_sec = bb.getInt() & 0xffffffffL;
			long ts_usec = bb.getInt() & 0xffffffffL;
			int incl_len = bb.getInt();
			int orig_len = bb.getInt();

			return new RecordHeader(ts_sec, ts_usec, incl_len, orig_len);
		}
	}

	public static class RecordHeader {
		private final long ts_sec; /* timestamp seconds */
		private final long ts_usec; /* timestamp microseconds */
		private final int incl_len; /* number of octets of packet saved in file */
		private final int orig_len; /* actual length of packet */

		public RecordHeader(long ts_sec, long ts_usec, int incl_len, int orig_len) {
			this.ts_sec = ts_sec;
			this.ts_usec = ts_usec;
			this.incl_len = incl_len;
			this.orig_len = orig_len;
		}

		public long timestampSeconds() {
			return ts_sec;
		}

		public long timestampSubseconds() {
			return ts_usec;
		}

		public int capturedLength() {
			return incl_len;
		}

		public int originalLength() {
			return orig_len;
		}
	}

	public static class GlobalHeader {
		private final int magic_number;
		private final short version_major;
		private final short version_minor;
		private final int thiszone;
		private final int sigfigs;
		private final int snaplen;
		private final int network;
		private final ByteOrder order;
		private final TimeUnit timeUnit;

		public GlobalHeader(int magic_number, ByteOrder order, TimeUnit timeUnit, short version_major, short version_minor,
		    int thiszone, int sigfigs, int snaplen, int network) {
			this.magic_number = magic_number;
			this.order = order;
			this.timeUnit = timeUnit;
			this.version_major = version_major;
			this.version_minor = version_minor;
			this.thiszone = thiszone;
			this.sigfigs = sigfigs;
			this.snaplen = snaplen;
			this.network = network;
		}

		public int magicNumber() {
			return magic_number;
		}

		public short versionMajor() {
			return version_major;
		}

		public short versionMinor() {
			return version_minor;
		}

		public int thiszone() {
			return thiszone;
		}

		public int sigfigs() {
			return sigfigs;
		}

		public int snaplen() {
			return snaplen;
		}

		public int network() {
			return network;
		}

		public ByteOrder byteOrder() {
			return order;
		}

		public TimeUnit timestampUnit() {
			return timeUnit;
		}
	}

	private static final class PcapRecordImpl implements PcapRecord {
		private final long timestamp;
		private final int capturedLength;
		private final int originalLength;
		private final ByteBuffer payload;
		private final int subProtocol;
		private final int index;

		public PcapRecordImpl(long timestamp, int index, int capturedLength, int originalLength, int subProtocol, ByteBuffer payload) {
			this.timestamp = timestamp;
			this.index = index;
			this.capturedLength = capturedLength;
			this.originalLength = originalLength;
			this.payload = payload;
			this.subProtocol = subProtocol;
		}

		@Override
		public long timestamp() {
			return timestamp;
		}

		@Override
		public int capturedLength() {
			return capturedLength;
		}

		@Override
		public int originalLength() {
			return originalLength;
		}

		@Override
		public ByteBuffer payload() {
			return payload.slice();
		}

		@Override
		public PcapRecord rootFrame() {
			return this;
		}

		@Override
		public PayloadFrame parentFrame() {
			return null;
		}

		@Override
		public int subProtocol() {
			return subProtocol;
		}

		@Override
		public int index() {
			return index;
		}

	}

	public static PcapReader create(Path path) throws IOException {
		FileChannel fileChannel =
		    path.getFileSystem().provider().newFileChannel(path, Collections.singleton(StandardOpenOption.READ));
		MappedByteBuffer buffer = fileChannel.map(MapMode.READ_ONLY, 0, fileChannel.size());
		GlobalHeader globalHeader = new GlobalHeaderReader().deserialize(buffer);
		buffer.order(globalHeader.byteOrder());
		return new PcapReader(globalHeader, buffer);
	}

	private final GlobalHeader header;
	private final ByteBuffer buffer;

	private PcapReader(GlobalHeader header, ByteBuffer buffer) {
		this.header = header;
		this.buffer = buffer;
	}

	@Override
	public Iterator<PcapRecord> iterator() {
		final ByteBuffer iteratorBuffer = buffer.slice();
		iteratorBuffer.order(header.byteOrder());
		final RecordHeaderReader reader = new RecordHeaderReader();
		return new Iterator<PcapRecord>() {
			private int index = 0;
			private PcapRecordImpl currentFrame = null;

			@Override
			public boolean hasNext() {
				if (currentFrame != null)
					return true;
				if (iteratorBuffer.remaining() < reader.size())
					return false;
				RecordHeader recordHeader = reader.deserialize(iteratorBuffer);
				int capturedLength = recordHeader.capturedLength();
				if (iteratorBuffer.remaining() < capturedLength)
					return false;

				int oldLimit = iteratorBuffer.limit();
				int endOfRecord = iteratorBuffer.position() + capturedLength;
				iteratorBuffer.limit(endOfRecord);
				currentFrame =
				    new PcapRecordImpl(TimeUnit.SECONDS.toNanos(recordHeader.timestampSeconds()) +
				        header.timestampUnit().toNanos(recordHeader.timestampSubseconds()), index++, recordHeader.capturedLength(),
				        recordHeader.originalLength(), header.network(), iteratorBuffer.slice());

				iteratorBuffer.limit(oldLimit);
				iteratorBuffer.position(endOfRecord);
				return true;
			}

			@Override
			public PcapRecord next() {
				if (!hasNext())
					throw new NoSuchElementException();
				PcapRecordImpl f = currentFrame;
				currentFrame = null;
				return f;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public int getLinkType() {
		return header.network();
	}

	public int getTZOffset() {
		return header.thiszone();
	}

	public <T> Iterable<T> decodeAs(final IteratorFactory<PcapRecord, T> b) {
		return new Iterable<T>() {
			@Override
			public Iterator<T> iterator() {
				return b.map(PcapReader.this.iterator());
			}
		};
	}
}
