package se.fnord.pcap;


public interface TcpSessionEvent {
	enum Direction {
		NONE {
			Direction reverse() {
				return this;
			}
		},
		FROM_SERVER {
			Direction reverse() {
				return FROM_CLIENT;
			}
		},
		FROM_CLIENT {
			Direction reverse() {
				return FROM_SERVER;
			}
		};

		abstract Direction reverse();
	};

	int index();

	TcpSessionId session();

	Direction direction();
}
