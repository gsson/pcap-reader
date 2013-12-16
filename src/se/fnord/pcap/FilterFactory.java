package se.fnord.pcap;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class FilterFactory<T, U extends T> implements IteratorFactory<T, U> {
	private FilterFunction<T, U> filter;

	private class FilteringIterator implements Iterator<U> {
		private final Iterator<T> from;
		private U next = null;

		public FilteringIterator(Iterator<T> from) {
			this.from = from;
		}

		@SuppressWarnings("unchecked")
        @Override
		public boolean hasNext() {
			if (next != null)
				return true;
			while (from.hasNext()) {
				T candidate = from.next();
				if (filter.test(candidate)) {
					next = (U) candidate;
					return true;
				}
			}
			return false;
		}

		@Override
		public U next() {
			if (!hasNext())
				throw new NoSuchElementException();
			U n = next;
			next = null;
			return n;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	public FilterFactory(FilterFunction<T, U> filter) {
		this.filter = filter;
	}

	@Override
	public Iterator<U> map(Iterator<T> from) {
		return new FilteringIterator(from);
	}

}
