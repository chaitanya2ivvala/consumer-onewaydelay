#define __STDC_FORMAT_MACROS
#include <caputils/caputils.h>
#include <caputils/log.h>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <netinet/ip.h>
#include <string>
#include <map>
#include <algorithm>

#define MAX_STREAM 4
static size_t num_streams = 0;

typedef struct packet_data {
	picotime timestamp;
	std::string mampid;
} packet_data;

typedef struct packet_id {
	packet_id()
		: seq(0)
		, num(0)
		, data(num_streams){}

	unsigned int seq;
	unsigned int num;
	std::vector<packet_data> data;
} packet_id;

static bool running = true;
static const char* program_name;
static const char* iface = NULL;
static uint32_t seek = 0;
static uint32_t count = 1500;
static unsigned int timeout = 60;
static size_t matched = 0;
static std::map<std::string, packet_id> table;
static const struct stream_stat* stream_stat = NULL;

static const char* shortopt = "i:s:c:t:h";
static struct option longopt[] = {
	{"iface",   required_argument, 0, 'i'},
	{"seek",    required_argument, 0, 's'},
	{"count",   required_argument, 0, 'c'},
	{"timeout", required_argument, 0, 't'},
	{"help",    no_argument,       0, 'h'},
	{0,0,0,0}, /* sentinel */
};

static void show_usage(){

	filter_from_argv_usage();
}

template <class T>
T min(T a, T b){ return a<b?a:b; }

static void handle_alarm(int signum){
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	timepico cur = timespec_to_timepico(ts);

	size_t pruned = 0;
	for ( auto it = table.begin(); it != table.end(); ) {
		const packet_id& id = it->second;
		const bool old = timepico_sub(cur, id.data[0].timestamp).tv_sec > timeout + 5; /* some slack */

		if ( old ) {
			pruned++;
			table.erase(it++);
		} else {
			++it;
		}
	}

	static char timestr[64];
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	fprintf(stderr, "%s: [%s] progress report: %'"PRIu64" packets read (%zd matched, %zd pruned, %zd in progress).\n",
	        program_name, timestr, (long int)0, matched, pruned, table.size());
	matched = 0;
}

static void handle_sigint(int signum){
	if ( running ){
		fprintf(stderr, "\rGot SIGINT, terminating graceful.\n");
		running = false;
	} else {
		fprintf(stderr, "\rGot SIGINT again, aborting.\n");
		abort();
	}
}

static void format(packet_id& pkt){
	fprintf(stdout, "%d", pkt.seq);

	std::sort(pkt.data.begin(), pkt.data.end(), [](const packet_data& a, const packet_data& b) -> bool {
		return timecmp(&a.timestamp, &b.timestamp) == -1;
	});
	//std::sort(pkt.data.begin(), pkt.data.end(), myobject);

	/* sort */
	// timepico cur = id.ts[0];
	 for ( unsigned int i = 1; i < num_streams; i++ ){
	// 	if ( timecmp(id.ts[i], cur) == -1 ){
	// 		const std::string tmp m = id.mampid[i];
	// 		const timepico t = id.ts[i];

	// 	}

	 	const timepico &a = pkt.data[i].timestamp;
	 	const timepico &b = pkt.data[i-1].timestamp;
	 	const timepico dt = timepico_sub(a, b);
		fprintf(stdout, ";%s;%d.%012"PRIu64";%s;%d.%012"PRIu64, pkt.data[i-1].mampid.c_str(), b.tv_sec, b.tv_psec, pkt.data[i].mampid.c_str(), a.tv_sec, a.tv_psec);
	 	fprintf(stdout, ";%d.%012"PRIu64, dt.tv_sec, dt.tv_psec);
	 }
	fprintf(stdout, "\n");
}

int main(int argc, char* argv[]){
  /* extract program name from path. e.g. /path/to/MArCd -> MArCd */
  const char* separator = strrchr(argv[0], '/');
  if ( separator ){
    program_name = separator + 1;
  } else {
    program_name = argv[0];
  }

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		exit(1); /* error already shown */
	}

	int op, option_index;
	while ( (op=getopt_long(argc, argv, shortopt, longopt, &option_index)) != -1 ){
		switch (op){
		case 'i': /* --iface */
			iface = optarg;
			break;

		case 's': /* --seek */
			seek = (size_t)atoi(optarg);
			break;

		case 'c': /* --count */
			count = (size_t)atoi(optarg);
			break;

		case 't': /* --timeout */
			timeout = atoi(optarg);
			break;

		case 'h': /* --help */
			show_usage();
			exit(0);
		}
	}

	if ( !iface ){
		fprintf(stderr, "%s: no interface specified, use --iface or --help to show usage.\n", program_name);
		exit(1);
	}

	struct itimerval tv = {
		{timeout, 0},
		{timeout, 0},
	};
	setitimer(ITIMER_REAL, &tv, NULL);
	signal(SIGALRM, handle_alarm);
	signal(SIGINT, handle_sigint);

	num_streams = argc - optind;
	stream_t st;
	if ( stream_from_getopt(&st, argv, optind, argc, iface, NULL, program_name, 0) != 0 ){
		exit(1); /* error already shown */
	}
	stream_stat = stream_get_stat(st);

	if ( num_streams < 2 ){
		fprintf(stderr, "%s: need at least two streams\n", program_name);
		exit(1);
	}

	if ( num_streams > MAX_STREAM ){
		fprintf(stderr, "%s: only up to %d streams supported.\n", program_name, MAX_STREAM);
		exit(1);
	}

	unsigned int gseq = 0;

	do {
		struct cap_header* cp;
		int ret = stream_read(st, &cp, &filter, NULL);
		if ( ret == EAGAIN ) continue;
		if ( ret == -1 ) break;

		const size_t offset = min(cp->len, seek);
		const size_t bytes = min(cp->len, min(cp->caplen, count)) - offset;
		if ( offset - bytes == 0 ) continue;


		char hex[33];
		unsigned char* _ = MD5((const unsigned char*)&cp->payload[offset], bytes, NULL);
		sprintf(hex, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		        _[0], _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], _[9], _[10], _[11], _[12], _[13], _[14], _[15]);

		const std::string hash(hex);
		auto it = table.find(hash);

		// fprintf(stderr, "%.8s\n", cp->mampid);
		// const struct ip* ip = find_ip_header(cp->ethhdr);
		// if ( ip ){
		// 	fprintf(stderr, "  src: %s\n", inet_ntoa(ip->ip_src));
		// 	fprintf(stderr, "  dst: %s\n", inet_ntoa(ip->ip_dst));
		// }
		// hexdump(stderr, (char*)&cp->payload[offset], bytes);
		// fprintf(stderr, "%s\n\n", hash.c_str());

		//print("%s\n", hash.c_str());
		if ( it != table.end() ){ /* match found */
			packet_id& id = it->second;

			/* find duplicates (e.g. arp) */
			unsigned int i;
			for ( i = 0; i < id.num; i++ ){
				if ( std::string(cp->mampid, 8) == id.data[i].mampid ){
					//fprintf(stderr, "Dup\n");
					break;
				}
			}
			if ( i < id.num ) continue;

			id.data[id.num] = {cp->ts, std::string(cp->mampid, 8)};
			if ( ++id.num == num_streams ){ /* passed all points */
				matched++;
				format(id);
				table.erase(it);
			}
		} else { /* no match */
			packet_id id;
			id.seq = ++gseq;
			id.num = 1;
			id.data[0] = {cp->ts, std::string(cp->mampid, 8)};
			table[hash] = id;
		}
	} while ( running );

	stream_close(st);
}
