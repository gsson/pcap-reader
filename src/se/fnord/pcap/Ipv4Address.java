package se.fnord.pcap;

public class Ipv4Address extends AbstractAddress {
	public Ipv4Address(byte[] bytes) {
	    super(bytes);
    }

	@Override
    public int length() {
	    return 4;
    }
	
	public int toInteger() {
		int ip = bytes[0] & 0xff;
		ip = (ip << 8) | (bytes[1] & 0xff);
		ip = (ip << 8) | (bytes[2] & 0xff);
		ip = (ip << 8) | (bytes[3] & 0xff);
		return ip;
	}
}
