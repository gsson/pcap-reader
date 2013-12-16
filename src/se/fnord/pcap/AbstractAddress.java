package se.fnord.pcap;

import java.util.Arrays;

public abstract class AbstractAddress implements Address {
	protected final byte[] bytes;

	public AbstractAddress(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] bytes() {
		return bytes.clone();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj.getClass() != AbstractAddress.class)
			return false;
		AbstractAddress other = (AbstractAddress) obj;
		return Arrays.equals(bytes, other.bytes);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(bytes);
	}
}
