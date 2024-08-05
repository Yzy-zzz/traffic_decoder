#ifndef _APP_STREAM_ENTRY_H_
#define _APP_STREAM_ENTRY_H_ 

#define STREAM_ENTRY_H_VERSION		(20190818)

/*
	CHN : 业务层调用解析层时session_state状态;
*/
#define SESSION_STATE_PENDING	0x01
#define SESSION_STATE_DATA		0x02
#define SESSION_STATE_CLOSE	0x04

//解析层调用业务层时的返回值；
#define PROT_STATE_GIVEME   0x01
#define PROT_STATE_DROPME	0x02
#define PROT_STATE_DROPPKT	0x04

//解析层插件调用业务层插件时传入参数
typedef struct _plugin_session_info
{
	unsigned short  plugid;			//plugid，平台分配
	char session_state;	//会话状态，PENDING,DATA,CLOSE
	char _pad_;			//补齐
	int buflen;			//当前字段长度
	long long prot_flag;	//当前字段的flag值
	void *buf;			//当前字段
	void* app_info;		//解析层上下文信息
}stSessionInfo;



#ifdef __cplusplus
extern "C" {
#endif


typedef char (*STREAM_CB_FUN_T)(const struct streaminfo *pstream,void **pme, int thread_seq,const void *ip_hdr);
typedef char (*IPv4_CB_FUN_T)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr);
typedef char (*IPv6_CB_FUN_T)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv6_hdr);


typedef char (*SAPP_PKT_CB_FUN_T)(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt);
typedef char (*SAPP_STREAM_FUN_T)(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);


/*参数描述：
	a_*, pstream:	本流上下文信息;
	raw_pkt:	原始包指针,获取相关信息使用get_opt_from_rawpkt()接口;
	pme:		私有数据指针;
	thread_seq：线程序号;

函数返回值描述：为下面四个值的运算

	APP_STATE_GIVEME：继续向本函数送包。
	APP_STATE_DROPME：不再向本函数送包。
	APP_STATE_FAWPKT：回注该数据包
	APP_STATE_DROPPKT：不回注该数据包
*/
char IPv4_ENTRY_EXAMPLE(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *ipv4_hdr);
char IPv6_ENTRY_EXAMPLE(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,const void *ipv6_hdr);
char TCP_ENTRY_EXAMPLE(const struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *ip_hdr);
char UDP_ENTRY_EXAMPLE(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *ip_hdr);

char SAPP_PKT_EXAMPLE(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt);
char SAPP_STREAM_EXAMPLE(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);

#define POLLING_STATE_WORK 0x80
#define POLLING_STATE_IDLE 0x40

/*
    每隔一定时间, 平台会调用当前接口, 无论网络中是否有数据包. 
    stream, pme, a_packet固定都是NULL, thread_seq即收包线程的序号.

    返回值:
        POLLING_STATE_WORK: 此次回调插件做了若干有意义的事情;
        POLLING_STATE_IDLE: 此次回调插件什么都没做, 或者想做而没做成, 比如非阻塞模式收包, 但实际没有收到包;
*/
char POLLING_ENTRY(struct streaminfo *stream,  void **pme, int thread_seq,void *a_packet);


/* 
	CHN : 业务层回调接口 ;
	ENG : business plug API ;
*/

char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);

int  libsapp_setup_env(int argc, char *argv[]);
void libsapp_destroy_env(void);


#ifdef __cplusplus
}
#endif


#endif

