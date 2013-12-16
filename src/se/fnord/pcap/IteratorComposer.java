package se.fnord.pcap;

import java.util.Iterator;

public class IteratorComposer<FROM, VIA, TO> implements IteratorFactory<FROM, TO> {
	private final IteratorFactory<FROM, VIA> first;
	private final IteratorFactory<VIA, TO> second;

	public IteratorComposer(IteratorFactory<FROM, VIA> first, IteratorFactory<VIA, TO> second) {
		this.first = first;
		this.second = second;
	}

	@Override
	public Iterator<TO> map(Iterator<FROM> from) {
		return second.map(first.map(from));
	}
}
