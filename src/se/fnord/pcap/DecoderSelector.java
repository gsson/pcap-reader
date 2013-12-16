package se.fnord.pcap;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class DecoderSelector<FROM, TO> implements IteratorFactory<FROM, TO> {
	private final DecoderFunctionSelector<FROM, TO> selector;

	private class DecodingIterator implements Iterator<TO> {
		private final Iterator<FROM> from;
		private TO next = null;

		public DecodingIterator(Iterator<FROM> from) {
			this.from = from;
		}

		@Override
		public boolean hasNext() {
			if (next != null)
				return true;
			while (from.hasNext()) {
				FROM candidate = from.next();
				final DecoderFunction<FROM, ? extends TO> decoder = selector.select(candidate);
				if (decoder == null)
					continue;
				next = decoder.decode(candidate);
				return true;
			}
			return false;
		}

		@Override
		public TO next() {
			if (!hasNext())
				throw new NoSuchElementException();
			TO n = next;
			next = null;
			return n;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	public DecoderSelector(DecoderFunctionSelector<FROM, TO> selector) {
		this.selector = selector;
    }

	@Override
	public Iterator<TO> map(Iterator<FROM> from) {
		return new DecodingIterator(from);
	}
}
