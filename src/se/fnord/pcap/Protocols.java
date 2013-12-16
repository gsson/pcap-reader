package se.fnord.pcap;

import java.util.HashMap;
import java.util.Map;

public class Protocols {
	private Protocols() {
		throw new IllegalAccessError();
	}

	public static <F, V, T> IteratorFactory<F, T> stack(IteratorFactory<F, V> first, IteratorFactory<V, T> second) {
		return new IteratorComposer<F, V, T>(first, second);
	}

	public static <F, V1, V2, T> IteratorFactory<F, T> stack(IteratorFactory<F, V1> first, IteratorFactory<V1, V2> second,
	    IteratorFactory<V2, T> third) {
		return stack(stack(first, second), third);
	}

	public static <F, V1, V2, V3, T> IteratorFactory<F, T> stack(IteratorFactory<F, V1> first, IteratorFactory<V1, V2> second,
	    IteratorFactory<V2, V3> third, IteratorFactory<V3, T> fourth) {
		return stack(stack(first, second, third), fourth);
	}

	public static final class SubProtocolDecoderBuilder<FROM extends PayloadFrame, TO> {
		private static class SubProtocolSelector<FROM extends PayloadFrame, TO> implements DecoderFunctionSelector<FROM, TO> {
			private final Map<Integer, DecoderFunction<FROM, ? extends TO>> decoders;
			private final DecoderFunction<FROM, ? extends TO> defaultDecoder;

			public SubProtocolSelector(Map<Integer, DecoderFunction<FROM, ? extends TO>> decoders,
			    DecoderFunction<FROM, ? extends TO> defaultDecoder) {
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

		private final Map<Integer, DecoderFunction<FROM, ? extends TO>> decoders = new HashMap<>();
		private DecoderFunction<FROM, ? extends TO> defaultDecoder = null;

		public SubProtocolDecoderBuilder<FROM, TO> addProtocol(int id, DecoderFunction<FROM, ? extends TO> decoder) {
			decoders.put(id, decoder);
			return this;
		}

		public SubProtocolDecoderBuilder<FROM, TO> setDefault(DecoderFunction<FROM, ? extends TO> decoder) {
			this.defaultDecoder = decoder;
			return this;
		}

		public IteratorFactory<FROM, TO> build() {
			return new DecoderSelector<>(new SubProtocolSelector<FROM, TO>(new HashMap<>(decoders), defaultDecoder));
		}
	}

	public static <FROM extends PayloadFrame, TO> SubProtocolDecoderBuilder<FROM, TO> select() {
		return new SubProtocolDecoderBuilder<FROM, TO>();
	}

	public static <F, T> IteratorFactory<F, T> select(DecoderFunctionSelector<F, T> selector) {
		return new DecoderSelector<>(selector);
	}
}
