package se.fnord.pcap;

import java.util.Map;

public class SubProtocolSelector<FROM extends PayloadFrame, TO> implements DecoderFunctionSelector<FROM, TO> {
	private final Map<Integer, DecoderFunction<FROM, ? extends TO>> decoders;
	private final DecoderFunction<FROM, ? extends TO> defaultDecoder;

	public SubProtocolSelector(Map<Integer, DecoderFunction<FROM, ? extends TO>> decoders, DecoderFunction<FROM, ? extends TO> defaultDecoder) {
		this.decoders = decoders;
		this.defaultDecoder = defaultDecoder;
    }

	@Override
	public DecoderFunction<FROM, ? extends TO> select(FROM value) {
		DecoderFunction<FROM, ? extends TO> decoderFunction = decoders.get(value.subProtocol());
		if (decoderFunction != null)
			return decoderFunction;
		return defaultDecoder;
	}

}
