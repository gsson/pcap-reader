package se.fnord.pcap;

public interface DecoderFunctionSelector<FROM, TO> {
	DecoderFunction<FROM, ? extends TO> select(FROM value);
}
