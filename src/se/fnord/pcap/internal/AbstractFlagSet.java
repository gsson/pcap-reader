package se.fnord.pcap.internal;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

import se.fnord.pcap.Flag;

public abstract class AbstractFlagSet<T extends Enum<T> & Flag> implements Set<T> {
	private final int flags;
	private final Class<T> type;
	private final T[] byIndex;

	@SuppressWarnings("unchecked")
	public static <U extends Enum<U> & Flag> U[] createIndex(Class<U> type) {
		U[] flags = type.getEnumConstants();
		U[] byIndex;

		int maxIndex = 0;
		for (U flag : flags)
			maxIndex = Math.max(maxIndex, flag.index());
		byIndex = (U[]) Array.newInstance(type, maxIndex + 1);
		for (U flag : flags)
			byIndex[flag.index()] = flag;
		return byIndex;
	}

	public static <U extends Enum<U> & Flag> int createMask(Class<U> type) {
		U[] flags = type.getEnumConstants();

		int mask = 0;
		for (U flag : flags)
			mask |= flag.bit();
		return mask;
	}

	protected AbstractFlagSet(int flags, Class<T> t, T[] byIndex) {
		this.flags = flags;
		this.type = t;
		this.byIndex = byIndex;
	}

	private T fromIndex(int index) {
		if (index < 0 || index >= byIndex.length)
			return null;
		return byIndex[index];
	}

	@Override
	public int size() {
		return Integer.bitCount(flags);
	}

	@Override
	public boolean isEmpty() {
		return flags == 0;
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean contains(Object o) {
		if (!type.isInstance(o))
			return false;
		T flag = (T) o;
		return (flags & flag.bit()) != 0;
	}

	@Override
	public Iterator<T> iterator() {
		return new Iterator<T>() {
			int bits = flags;

			@Override
			public boolean hasNext() {
				return bits != 0;
			}

			@Override
			public T next() {
				if (!hasNext())
					throw new NoSuchElementException();
				int bit = Integer.lowestOneBit(bits);
				bits -= bit;
				return fromIndex(Integer.numberOfTrailingZeros(bit));
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	@Override
	public Object[] toArray() {
		final Object[] o = new Object[size()];
		int i = 0;
		for (T flag : this)
			o[i++] = flag;
		return o;
	}

	@SuppressWarnings("unchecked")
	@Override
	public <U> U[] toArray(U[] a) {
		final int size = size();
		if (a.length < size)
			a = (U[]) Array.newInstance(a.getClass().getComponentType(), size);
		int i = 0;
		for (T flag : this)
			a[i++] = (U) flag;
		if (a.length > size)
			a[size] = null;
		return a;
	}

	@Override
	public boolean add(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		if (c instanceof AbstractFlagSet<?>) {
			AbstractFlagSet<?> other = (AbstractFlagSet<?>) c;
			return type == other.type && (flags & other.flags) == other.flags;
		}
		for (Object o : c)
			if (!contains(o))
				return false;
		return true;
	}

	@Override
	public boolean addAll(Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Set<?>))
			return false;
		if (obj instanceof AbstractFlagSet<?>) {
			AbstractFlagSet<?> other = (AbstractFlagSet<?>) obj;
			return type == other.type && flags == other.flags;
		}
		Set<?> other = (Set<?>) obj;
		return size() == other.size() && containsAll(other);
	}

	@Override
	public int hashCode() {
		int code = 0;
		for (T flag : this)
			code += flag.hashCode();
		return code;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("[");
		Iterator<T> i = iterator();
		if (i.hasNext()) {
			sb.append(i.next().name());
			while (i.hasNext()) {
				sb.append(", ").append(i.next().name());
			}
		}

		sb.append("]");
		return sb.toString();
	}
}
