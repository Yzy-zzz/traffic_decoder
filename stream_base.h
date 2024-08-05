#ifndef _APP_STREAM_BASE_H_
#define _APP_STREAM_BASE_H_ 

#define STREAM_BASE_H_VERSION		(20210621)

#include <sys/types.h>
#include <netinet/in.h>            
#include <netinet/ip.h>            
#include <netinet/ip6.h>   
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <linux/if_ether.h>   
#include <stdlib.h>
#include <string.h>

#ifndef UINT8
typedef unsigned char		UINT8;
#endif
#ifndef UCHAR
typedef unsigned char		UCHAR;
#endif
#ifndef UINT16
typedef unsigned short		UINT16;
#endif

#ifndef UINT32
typedef unsigned int		UINT32;
#endif
#ifndef UINT64
typedef unsigned long long	UINT64;
#endif

/* CHN : 流的方向定义 */
/* ENG : stream direction definition*/
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 			0x03

/* CHN : 网络底层传输方向定义,串联模式有意义 */
/* ENG : network topology route direction, is valid in serial mode */
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 		0x01

/* CHN : 单包的类型定义 */
/* ENG : single packet type definition */
#define PKT_TYPE_NORMAL  			(0x0)	/* normal, common */
#define PKT_TYPE_IPREBUILD 			(1<<0)  /* ip frag reassembled packet;  ip碎片重组报文 */
#define PKT_TYPE_TCPUNORDER 		(1<<1)  /* TCP out of order packet;  TCP乱序报文 */
#define PKT_TYPE_TCPREORDER 		(1<<2)  /* TCP sequential packet;  TCP乱序排序好的数据包 */ 
#define PKT_TYPE_TCPRETRANS 		(1<<3)  /* TCP retransmit packet;  TCP重传报文 */
#define PKT_TYPE_IP_FRAG			(1<<4)  /* IP frag packet;  IP分片包 */
#define PKT_TYPE_IP_FRAG_LAST		(1<<5)  /* last IP frag packet;  同属于一个原始完整IP包的最后一个IP分片包 */

/* CHN : 地址类型定义, 可通过函数 addr_type_to_string() 转成字符串形式. */
/* ENG : address type, transform to string mode by call addr_type_to_string(). */
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, struct stream_tuple4_v4 */
	ADDR_TYPE_IPV6,				/* 2, struct stream_tuple4_v6 */
	ADDR_TYPE_VLAN,				/* 3, 802.1Q */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,			/* 5 */
	ADDR_TYPE_GRE,				/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,		/* 8 */
	ADDR_TYPE_TCP,				/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	__ADDR_TYPE_IP_PAIR_V4,		/* 12, ipv4 layer in tunnel mode */
	__ADDR_TYPE_IP_PAIR_V6,		/* 13, ipv6 layer in tunnel mode */
	ADDR_TYPE_PPP,				/* 14 */
	ADDR_TYPE_PPTP,			/* 15 */
	ADDR_TYPE_MAC_IN_MAC,		/* 16 */
	ADDR_TYPE_GPRS_TUNNEL,      /* 17 */
	ADDR_TYPE_VXLAN,			/* 18 */
	__ADDR_TYPE_MAX,			/* 19 */
};

#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1


/* CHN : 应用层看到的链接状态定义 */
/* ENG : stream state for protocol or business plug*/
#define OP_STATE_PENDING   0
#define _OP_STATE_OBSOLETE 1  /* is obsolete */
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

/* CHN : 应用层返回结果定义 */
/* ENG : return value of plug */
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10


#define APP_STATE_KILL_FOLLOW 0x40 /* 强制CLOSE当前插件后续的所有插件 */
#define APP_STATE_KILL_OTHER  0x80 /* 强制CLOSE除当前插件外的所有插件 */


/* CHN : 流的类型定义 */
/* ENG : stream type */
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* No stream concept indeed, such as vlan, IP, etc.;  无流的概念, 如VLAN, IP层等 */
	STREAM_TYPE_TCP,
	STREAM_TYPE_UDP,	 /* there is no stream of UDP in RFC, but in MESA platform, we build a UDP stream with same tuple4 packet */
	STREAM_TYPE_VLAN,
	STREAM_TYPE_SOCKS4,
	STREAM_TYPE_SOCKS5,
	STREAM_TYPE_HTTP_PROXY,
	STREAM_TYPE_PPPOE,
	STREAM_TYPE_L2TP,
	STREAM_TYPE_OPENVPN,
	STREAM_TYPE_PPTP,	
	STREAM_TYPE_ISAKMP,
};

/*
   CHN: 流的底层承载隧道类型, 
   	   不同于stream_type_t, 比如当前流为STREAM_TYPE_TCP, 但底层隧道类型可能是STREAM_TUNNLE_PPTP.
        因为隧道可能是多种不同类型嵌套组合, 只记录最底层(离MAC层最近的)隧道类型.
*/
enum stream_carry_tunnel_t{
	STREAM_TUNNLE_NON 		= 0, 	/* default is 0, not tunnel; 默认为0, 非隧道; */
	STREAM_TUNNLE_6OVER4 	= 1 << 0,
	STREAM_TUNNLE_4OVER6	= 1 << 1,
	STREAM_TUNNLE_GRE		= 1 << 2,
	STREAM_TUNNLE_IP_IN_IP	= 1 << 3,
	STREAM_TUNNLE_PPTP		= 1 << 4,
	STREAM_TUNNLE_L2TP		= 1 << 5,
	STREAM_TUNNLE_TEREDO	= 1 << 6,
	STREAM_TUNNEL_GPRS_TUNNEL = 1 << 7,
	STREAM_TUNNEL_MULTI_MAC = 1 << 8, /* is obsoulte */
};

typedef struct raw_ipfrag_list{
    void *frag_packet; /* 非ip包头, 从底层网卡获取的原始包头 */
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;


#ifndef STRUCT_TUPLE4_DEFINED
#define STRUCT_TUPLE4_DEFINED (1)
/* compat for start, papp;  兼容start, papp */
struct tuple4 {
  u_int saddr;
  u_int daddr;
  u_short source;
  u_short dest;
};
#endif

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

/* network-order */
struct stream_tuple4_v4{
	UINT32 saddr;	/* network order */
	UINT32 daddr;	/* network order */
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#ifndef IPV6_ADDR_LEN
#define IPV6_ADDR_LEN	(sizeof(struct in6_addr))
#endif

struct stream_tuple4_v6
{
	UCHAR saddr[IPV6_ADDR_LEN] ;
	UCHAR daddr[IPV6_ADDR_LEN] ;
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#define GRE_TAG_LEN 		(4)
struct layer_addr_gre
{
	UINT16 call_id; /* network order */
};


#define VLAN_ID_MASK		(0x0FFF)
#define VLAN_TAG_LEN 		(4)
#define MAX_VLAN_ADDR_LAYER (8)


struct single_layer_vlan_addr{     /* refer to https://en.wikipedia.org/wiki/IEEE_802.1Q */
	unsigned short TPID; /* Tag protocol identifier, network order */
	unsigned char PCP; /* Priority code point */
	unsigned char DEI; /* Drop eligible indicator  */
	unsigned short VID;  /* VLAN identifier, network order */
};


struct layer_addr_vlan
{
	struct single_layer_vlan_addr c2s_addr_array[MAX_VLAN_ADDR_LAYER];
	struct single_layer_vlan_addr s2c_addr_array[MAX_VLAN_ADDR_LAYER];
	UCHAR c2s_layer_num;
	UCHAR s2c_layer_num;
};


struct layer_addr_pppoe_session
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#endif
  	unsigned char code;
	unsigned short session_id;
};

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN		(6)
#endif

struct layer_addr_mac
{
	/* 
	   C2S和S2C方向来自不同的链路和设备, 会导致两个方向的mac地址全不一样, 反向注入时不能用传统方式, 即简单的颠倒src和dst,
	   修改定义如下, mirror模式下, 还是存储在src_addr中,
	   API不同了, ABI还是向前兼容的, 结构体内存分布与之前的一致. 
	*/
	struct ethhdr src_addr;
	struct ethhdr dst_addr;
	
	//UCHAR dst_mac[MAC_ADDR_LEN]; /* network order */
	//UCHAR src_mac[MAC_ADDR_LEN]; /* network order */
};

struct layer_addr_ipv4
{
	UINT32 saddr; 	/* network order */
	UINT32 daddr; 	/* network order */
	/* 2014-04-21 lijia add, 
	   为了节约内存空间、和处理效率, 不强制按协议层次处理,
	   IP层和TCP层做为一个层,
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   为了节约内存空间、和处理效率, 不强制按协议层次处理,
	   IP层和TCP层做为一个层,
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;/* network order */
	UINT16 dest;/* network order */
};

struct layer_addr_tcp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_udp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};


struct layer_ppp_hdr{
	unsigned char address;
	unsigned char control;
	unsigned short protocol;	/* network order */ 		
}__attribute__((packed));

/* 一般情况下, address,control都是固定不变的,都是0xFF,0x03, ppp hdr是可以压缩以节约贷款,只传输一个字节的protocol字段 */
struct layer_compress_ppp_hdr{
	unsigned char protocol;		
};	


struct layer_addr_l2tp_v2_t{
	UINT16 tunnelid_C2S; /* network order, 以传输层创建流的方向为准 */
	UINT16 tunnelid_S2C; /* network order, 以传输层创建流的方向为准 */
	UINT16 sessionid_C2S; /* network order, 以传输层创建流的方向为准 */
	UINT16 sessionid_S2C; /* network order, 以传输层创建流的方向为准 */
	unsigned char seq_present_C2S;
	unsigned char seq_present_S2C;
	unsigned char ppp_hdr_compress_enable;
	union{
		struct layer_ppp_hdr ppp_hdr;
		struct layer_compress_ppp_hdr compress_ppp_hdr;
	};
};

struct layer_addr_l2tp_v3_t{
	UINT32 sessionlid; /* network order */
};
		
struct layer_addr_l2tp
{
	UCHAR version; /* v2 or v3 */
	union
	{	
 		struct layer_addr_l2tp_v2_t l2tp_addr_v2;
		struct layer_addr_l2tp_v3_t l2tp_addr_v3;
	}l2tpun;
};

#define MAX_MPLS_ADDR_LAYER 4

struct single_layer_mpls_addr{ /* refer to RFC3032 */
	unsigned int label; /* network order */
	unsigned char experimental;
	unsigned char bottom;
	unsigned char ttl;
};

/* 
    MPLS有可能是多层嵌套, sapp把多层合并处理, 目前最大支持4层, 层次序号由外到内排列, 0表示最外层, 3表示最内层 
    对于一个内层TCP/UDP流来说, 底层MPLS两个方向的地址可能不一样, 分别记为cs2_addr, s2c_addr.
*/
struct layer_addr_mpls
{
	struct single_layer_mpls_addr c2s_addr_array[MAX_MPLS_ADDR_LAYER]; 
	struct single_layer_mpls_addr s2c_addr_array[MAX_MPLS_ADDR_LAYER]; 
    char c2s_layer_num; /* 实际mpls层数 */
    char s2c_layer_num; /* 实际mpls层数 */
	char c2s_has_ctrl_word;
	char s2c_has_ctrl_word;
    unsigned int c2s_mpls_ctrl_word; /* refer to RFC4623 */
    unsigned int s2c_mpls_ctrl_word; /* refer to RFC4623 */
};


struct layer_addr_pptp
{
	UINT16 C2S_call_id;	/* C2S以传输层协议方向为准, TCP SYN为C2S, UDP源端口大的为C2S, callid, network order */
	UINT16 S2C_call_id;	/* S2Ck以传输层协议方向为准, TCP SYN/ACK为S2C, UDP目的端口大的为S2C, callid, network order */
};

struct layer_addr_gtp
{
	unsigned int teid_c2s; /* network order */
	unsigned int teid_s2c; /* network order */
}__attribute__ ((aligned (1)));

#define MAC_IN_MAC_HDR_LEN	(sizeof(struct mesa_ethernet_hdr) +  sizeof(struct mesa_ethernet_hdr))
struct layer_addr_mac_in_mac
{
	UCHAR outer_dst_mac[MAC_ADDR_LEN]; /* 最外层mac地址, network order */
	UCHAR outer_src_mac[MAC_ADDR_LEN]; /* 最外层mac地址, network order */
	UCHAR inner_dst_mac[MAC_ADDR_LEN]; /* 内层mac地址, network order */
	UCHAR inner_src_mac[MAC_ADDR_LEN]; /* 内层mac地址, network order */
};

struct single_layer_addr_vxlan
{
	UINT16 vlan_id; /* network order */
	UCHAR flag;
	UCHAR dir;
	UCHAR link_id;
	UCHAR link_type;
};


struct layer_addr_vxlan
{
	struct single_layer_addr_vxlan C2S_vxlan_addr;
	struct single_layer_addr_vxlan S2C_vxlan_addr;
};


struct layer_addr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;	
	UCHAR pkttype;	   	/* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR pktipfragtype;	/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *tuple4_v4;
		struct stream_tuple4_v6 *tuple4_v6;
		struct layer_addr_ipv4	*ipv4;
		struct layer_addr_ipv6	*ipv6;
		struct layer_addr_vlan	*vlan;
		struct layer_addr_mac	*mac;
		struct layer_addr_gre	*gre;
		struct layer_addr_tcp	*tcp;
		struct layer_addr_udp	*udp;
		struct layer_addr_pppoe_session *pppoe_ses;		
		struct layer_addr_l2tp	*l2tp;
		struct layer_addr_pptp	*pptp;
		struct layer_addr_mac_in_mac *mimac;
        struct layer_addr_gtp *gtp;
        struct layer_addr_mpls *mpls;
		struct layer_addr_vxlan *vxlan;
        void 					*paddr;
	};

};

/* CHN : 保留此结构用于和papp兼容, 用作指针时, 可与struct layer_addr强转 */
/* ENG : compat for papp, can be transform to struct layer_addr pointer */
struct ipaddr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;
	UCHAR  pkttype;	  /* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR  pktipfragtype;	   		/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *v4;
		struct stream_tuple4_v6 *v6;
		void *paddr;
	};

};

struct tcpdetail
{
	void  *pdata;		 
	UINT32 datalen;		
	UINT32 lostlen;		/* lost data len, not accumulated, current procedure */
	UINT32 serverpktnum; 	/* C2S, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientpktnum;  	/* S2C, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 serverbytes;   	/* C2S, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientbytes;     /* S2C, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct udpdetail
{
 	void *pdata;		     
 	UINT32 datalen;			 
	UINT32 pad;			
	UINT32 serverpktnum; 	 /* C2S, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientpktnum;	/* S2C, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 serverbytes;	/* C2S, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientbytes;	/* S2C, you should better use stream_project.h : struct udp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct streaminfo
{
	struct layer_addr addr;      
	struct streaminfo *pfather; /* this stream's carry layer stream; 上层流结构体 */
	UCHAR type;			/* stream type, definition in enum stream_type_t */
	UCHAR threadnum;	     
	UCHAR  dir;           	/*  valid in all stream life, current stream direction state, 0x01:c-->s; 0x02:s-->c; 0x03 c<-->s; */
	UCHAR  curdir;         /* valid in current procedure, current packet direction, 0x01:c-->s;  0x02:s-->c */
	UCHAR  opstate;		/* stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  pktstate;	/* for TCPALL plug, stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  routedir;	     /* network topology route direction, is valid in serial mode */
	UCHAR  stream_state;	/* stream management state, for example, in TCP stream, maybe SYN, DATA, NOUSE */
	UINT32 hash_index;		/* stream hash index, maybe reduplicate with other stream when hash algorithm collide */      
	UINT32 stream_index;    /* stream global index per thread  */	
	union
	{
		struct tcpdetail *ptcpdetail;
		struct udpdetail *pudpdetail;
		void   *pdetail;
	};
 };


typedef struct {
	unsigned int type;
	unsigned int length;
	union{
		char	char_value;
		short	short_value;
		int	int_value;
		long	long_value;
		char	array_value[8];
		void	*ptr_value; /* more than 8bytes data, or complex struct. */
	};
}SAPP_TLV_T;

#ifdef __cplusplus
extern "C" {
#endif

/* CHN : 内存管理相关函数, 基于平台的插件必须使用此类函数申请或释放内存 */
/* ENG : memory management function, plugs must call these functions instead of malloc, free in <stdlib.h> */
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

/* CHN : 获取当前系统运行的并发处理线程总数 */
/* ENG : get current total thread of platfomr */
int get_thread_count(void);

/* CHN : 将地enum addr_type_t址类型转换成可打印的字符串形式 */
/* ENG : transform binary addr_type_t to string mode */
const char *addr_type_to_string(enum addr_type_t type);

/*
	ENG : transform tuple4 to string mode, must used in packet process thread context;
	CHN : 将layer_addr地址转换成字符串形式, 必须用在包处理线程.
*/
const char *printaddr (const struct layer_addr *paddrinfo, int threadindex);

/*
	ENG : a reentrant version of printaddr, thread safe;
	CHN : printaddr的可重入版本, 是线程安全的.
*/
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len);


/*
	ENG : transform layer address to string mode, must used in packet process thread context, 
	      the return value is read-only, user can't free it;
	CHN : 将layer_addr地址转换成字符串形式, 必须用在包处理线程, 返回的指针为只读, 使用者不必free.
*/
const char *layer_addr_ntop(const struct streaminfo *pstream);

/*
	ENG : a reentrant version of layer_addr_ntop, thread safe, return a pointer to the destination string 'out_buf';
	CHN : layer_addr_ntop_r的可重入版本, 是线程安全的, 返回的指针执向使用者提供的out_buf, 便于代码组织.
*/
char *layer_addr_ntop_r(const struct streaminfo *pstream, char *out_buf, int out_buf_len);

/*
	ENG : transform layer type to abbr string mode, is reentrant, the return value is read-only, user can't free it;.
	CHN : 将layer_addr地址类型转换成缩写字符串形式, 可重入线程安全, 返回的指针为只读, 使用者不必free..
*/
const char *layer_addr_prefix_ntop(const struct streaminfo *pstream);


/* 
	ENG : duplicate a same layer_addr struct, memory obtained with malloc(3);
	CHN : 复制一个完全相同的layer_addr结构体, 内存通过malloc(3)获取.
*/
struct layer_addr * layer_addr_dup(const struct layer_addr *paddrinfo);

/* 
	ENG: used to free all memory of paddrinfo;
	CHN: 用于释放paddrinfo内存.
*/
void layer_addr_free(struct layer_addr *paddrinfo);


/* 
	ENG : duplicate a same streaminfo list, memory obtained with malloc(3);
	CHN : 复制一个完全相同的streaminfo结构体及父流结构, 内存通过malloc(3)获取.
*/
struct streaminfo *streaminfo_dup(const struct streaminfo *stream);

/* 
	ENG: used to free all memory of streaminfo;
	CHN: 用于释放结构体及父流结构的内存.
*/
void streaminfo_free(struct streaminfo *stream);


/* 
	addr list transform function, like inet_ntop(), inet_pton(),
	use '<' as delimitation between layer,
	if direction is double, for ip, port, use '-' as delimitation between source and destination,
	
	for example:
		"T4T:6005-1673<IP4:61.147.112.53-11.215.62.23<MAC:0000ea60040d-0200000003b6"

	args:
		pstream	: stream info;
		dst		: buf to store result;
		size		: dst buf's size;
		addr_list_str: addr list string;
		thread_index : thread index;

	返回值:
		>0:转换后的结果实际占用内存长度, stream_addr_list_ntop()包含了字符串末尾的'\0';
		-1:dst缓存空间长度不足;
		-2:格式错误;
		-3:其他错误;
*/
int stream_addr_list_ntop(const struct streaminfo *pstream, char *dst, int size);
int stream_addr_list_pton(const char *addr_list_str, void *dst, int size, int thread_index);

/*
	TCP,UDP流模式下, 获取当前IP包的原始分片包.
*/
const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream);

/*
	IP插件模式下, 获取当前IP包的原始分片包.
*/
const raw_ipfrag_list_t *ip_plug_get_raw_ipfrag_list(int thread_num, enum addr_type_t addr_type);


/*
	因为隧道、嵌套协议等原因, 输入一个纯四元组, 实际有可能查询到多个streaminfo,
	比如以下两个流:
		(1) tuple4->gtp->ip->udp->ethernet;
		(2) tuple4->l2tp->ip->udp->ethernet;
	如果隧道内层使用私有地址, 在一些极端凑巧的情况下, 流1和流2的内层tuple4可能是一样的, 但sapp会创建两个不同的streaminfo.

	输入参数:
		thread_index: 线程id;
		tuple4v4 or tuple4v6: 四元组地址, 源、目的地址顺序无要求, C2S, S2c方向均可;
		streamtype: 只支持两种类型, STREAM_TYPE_TCP or STREAM_TYPE_UDP;
		array_max_num: 数组streaminfo_array的最大元素个数.

	输出参数: 
		streaminfo_array: 查询到的符合输入四元组地址的streaminfo结构体指针.

	返回值:
	    -1: error;
		 0: 没有对应的streaminfo结构;
		>0: 实际找到streaminfo结构的数量;
*/
int find_streaminfo_by_addrv4(int thread_index, const struct stream_tuple4_v4 *tuplev4, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);
int find_streaminfo_by_addrv6(int thread_index, const struct stream_tuple4_v6 *tuplev6, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);


#ifdef __cplusplus
}
#endif

#endif

