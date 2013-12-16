package se.fnord.pcap;


public interface FilterFunction<T, U extends T> {
	public boolean test(T from);
}
