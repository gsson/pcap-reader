package se.fnord.pcap;

import java.util.Iterator;

public class DecoderFactory<FROM extends PayloadFrame, TO> implements IteratorFactory<FROM, TO> {
	private final DecoderFunction<FROM, TO> decoder;

	private class DecodingIterator implements Iterator<TO> {
		private final Iterator<FROM> from;

		public DecodingIterator(Iterator<FROM> from) {
			this.from = from;
		}

		@Override
		public boolean hasNext() {
			return from.hasNext();
		}

		@Override
		public TO next() {
			return decoder.decode(from.next());
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	public DecoderFactory(DecoderFunction<FROM, TO> decoder) {
		this.decoder = decoder;
	}

	@Override
	public Iterator<TO> map(Iterator<FROM> from) {
		return new DecodingIterator(from);
	}
}
