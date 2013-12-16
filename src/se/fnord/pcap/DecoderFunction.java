package se.fnord.pcap;


public interface DecoderFunction<FROM, TO> {
	public TO decode(FROM from);
}
