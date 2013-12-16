import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static se.fnord.pcap.Protocols.stack;
import static se.fnord.pcap.TcpSessionEvent.Direction.FROM_SERVER;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import se.fnord.pcap.FilterFactory;
import se.fnord.pcap.FilterFunction;
import se.fnord.pcap.IteratorFactory;
import se.fnord.pcap.PayloadFrame;
import se.fnord.pcap.PcapReader;
import se.fnord.pcap.PcapRecord;
import se.fnord.pcap.Protocols;
import se.fnord.pcap.TcpAssembler;
import se.fnord.pcap.TcpDecoder;
import se.fnord.pcap.TcpFrame;
import se.fnord.pcap.TcpSessionData;
import se.fnord.pcap.TcpSessionEvent;
import se.fnord.pcap.TcpSessionId;
import se.fnord.pcap.TcpSessionMissingData;
import se.fnord.pcap.decoder.EthernetDecoder;
import se.fnord.pcap.decoder.Ipv4Decoder;
import se.fnord.pcap.decoder.Ipv4Frame;
import se.fnord.pcap.decoder.SLLDecoder;

public class TcpExtract {

	private static IteratorFactory<PcapRecord, TcpSessionEvent> decoder(final int serverPort) {
		IteratorFactory<PcapRecord, PayloadFrame> eth =
		    Protocols.<PcapRecord, PayloadFrame> select().addProtocol(1, new EthernetDecoder<PcapRecord>())
		        .addProtocol(113, new SLLDecoder<PcapRecord>()).build();

		IteratorFactory<PayloadFrame, Ipv4Frame> ip =
		    Protocols.<PayloadFrame, Ipv4Frame> select().addProtocol(0x0800, new Ipv4Decoder<>()).build();

		IteratorFactory<Ipv4Frame, TcpFrame> tcp =
		    Protocols.<Ipv4Frame, TcpFrame> select().addProtocol(6, new TcpDecoder<Ipv4Frame>()).build();

		IteratorFactory<TcpFrame, TcpSessionEvent> tcpSession =
		    stack(new TcpAssembler(), new FilterFactory<>(new FilterFunction<TcpSessionEvent, TcpSessionEvent>() {
			    @Override
			    public boolean test(TcpSessionEvent from) {
				    // return from.session().serverPort() == serverPort;
				    return true;
			    }
		    }));
		return stack(eth, ip, tcp, tcpSession);
	}

	private static final ByteBuffer MISSING_DATA = ByteBuffer.wrap("XXX".getBytes(Charset.forName("UTF-8")));

	private static void extractPackets(Path destination, Iterable<TcpSessionEvent> events) throws IOException {
		for (TcpSessionEvent f : events) {
			if (f instanceof TcpSessionData) {
				TcpSessionData d = (TcpSessionData) f;
				FileChannel w = FileChannel.open(destination.resolve(formatName("packet", d)), TRUNCATE_EXISTING, WRITE, CREATE);
				w.write(d.payload());
				w.close();
			}
		}
	}

	private static void extractStream(Path destination, Iterable<TcpSessionEvent> events) throws IOException {
		Map<TcpSessionId, FileChannel> streams_to_client = new HashMap<>();
		Map<TcpSessionId, FileChannel> streams_to_server = new HashMap<>();
		for (TcpSessionEvent f : events) {
			Map<TcpSessionId, FileChannel> streams = f.direction() == FROM_SERVER ? streams_to_client : streams_to_server;
			FileChannel w = streams.get(f.session());

			if (f instanceof TcpSessionData) {
				if (w == null) {
					w = FileChannel.open(destination.resolve(formatName("stream", f)), TRUNCATE_EXISTING, WRITE, CREATE);
					streams.put(f.session(), w);
				}
				TcpSessionData d = (TcpSessionData) f;

				w.write(d.payload());
			}
			else if (f instanceof TcpSessionMissingData) {
				if (w != null)
					w.write(MISSING_DATA.slice());
			}
		}

		for (FileChannel c : streams_to_client.values())
			c.close();
		for (FileChannel c : streams_to_server.values())
			c.close();

	}

	private static String formatName(String type, TcpSessionEvent f) {
		return String.format("%s-%d-%d-%d-%s.txt", type, f.index(), f.session().clientPort(), f.session().serverPort(),
		    f.direction());
	}

	public static void main(String[] args) throws IOException {
		PcapReader reader = PcapReader.create(Paths.get("/path/to/file.pcap"));
		Path destination = Paths.get("/tmp");
		extractStream(destination, reader.decodeAs(decoder(3996)));
	}

}
