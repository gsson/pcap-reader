package se.fnord.pcap;


public class IdentityDecoderFunction<FROM> implements DecoderFunction<FROM, FROM> {
	@Override
	public FROM decode(FROM from) {
		return from;
	}
}
