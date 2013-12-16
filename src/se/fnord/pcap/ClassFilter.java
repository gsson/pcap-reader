package se.fnord.pcap;


public class ClassFilter<T, U extends T> implements FilterFunction<T, U> {
	private final Class<U> filter;

	public ClassFilter(Class<U> filter) {
		this.filter = filter;
	}

	@Override
	public boolean test(T from) {
		return filter.isInstance(from);
	}
}
