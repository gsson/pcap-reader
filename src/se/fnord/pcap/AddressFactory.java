package se.fnord.pcap;

public interface AddressFactory<T extends Address> {
	public T create();
}
