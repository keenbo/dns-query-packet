#include "util_dns.h" 

#define MAX_PACKET_SIZE 65536
#define DNS_SERVER_IP "114.114.114.114"
#define DNS_SERVER_PORT 53
/*
 * int get_mx_ip(const char *domain_name,char *ip,int len);
 * */

#define _DNS_RETURN(cond,ret) {\
	if(cond)\
	return ret;\
}

static int dns_packet_host_to_dynamic_data(void *dst,int dst_len,const char *host);
static int dns_packet_dynamic_data_read(void *dst,int dst_len,void *src,unsigned int src_len,
                                       void *base/*dns packet base address*/);
static int dns_packet_header_flag_to_flagvar(struct dns_packet_header *packet);
static int dns_packet_header_flagvar_to_flag(struct dns_packet_header *packet);
static int dns_packet_header_to_bytes(struct dns_packet_header *packet ,
                                      void *data,unsigned int data_len);
static void print_to_hex(const void *data,unsigned int data_len);
static void print_dns_packet(struct dns_packet_header *packet);
static int dns_packet_header_parse(void *data,unsigned int data_len,
                                   struct dns_packet_header *packet);
static int dns_answer_record_parse(void *data,unsigned int data_len,
                                   void *base/*dns packet base address*/,
                                   struct dns_answer_record *record);


/* 192.168.1.1 ->  3 1 9 2 3 1 6 8 1 1 1 1 0 */
static int dns_packet_host_to_dynamic_data(void *dst,int dst_len,const char *host)
{

    int str_len=strlen(host); 
    int len=str_len+2;
    if(dst_len<len)
        return -1;
    char *p=(char *)dst; 
    p[0]='.';
    for(int i=0;i<str_len;i++)
        p[i+1]=host[i];
    p[len-1]='.';

    int i=len-1;
    char c=0;
    /* .192.168.1.1. -> 3 192 3 168 1 1 1 1 0  */
    while(i>=0)
    {
        //printf("i:%d,%c,==.?%d\n",i,p[i],p[i]=='.');
        if(p[i]=='.')
        {
            p[i]=c;
            c=0;
        }else{
            c++; 
        }
        i--;
    }
    return len;
}


static int dns_packet_dynamic_data_read(void *dst,int dst_len,
                                        void *src,unsigned int src_len,
                                        void *base/*dns packet base address*/)
{

	unsigned char *s=(unsigned char*)src;
	unsigned char *d=(unsigned char*)dst;
	unsigned int src_off_set=0;
	unsigned int dst_off_set=0;
    int ret;
	_DNS_RETURN(src_off_set>=src_len,0);
	while(s[src_off_set]!=0)
	{
		/* size,xxx,size,xxx...... -> 192.168.1.108 or baidu.com */
		unsigned char read_len=s[src_off_set];
		if(read_len>0&&read_len<64 )
		{
            /* check left size enough */
            _DNS_RETURN(
                (dst_off_set+read_len+1)
                >= dst_len,0);
            _DNS_RETURN(
                (src_off_set+read_len+1)>=src_len,0);
            memcpy(d+dst_off_set,s+src_off_set+1,read_len);
            dst_off_set += read_len;
            src_off_set += read_len + 1;

            /* read next size to decide copy dot<.> if not end */
            if(s[src_off_set]!=0)
            d[dst_off_set]='.';
            else 
            d[dst_off_set]=(char)0;	
            dst_off_set++;
        }else if((3<<6) & read_len)
        /* 1100,0000 -> compress flag */
        {
            /* left 14 bit is off_set*/
            unsigned int compress_off_set;
            compress_off_set = (read_len-(3<<6))<<8;
            compress_off_set += s[src_off_set+1];
            unsigned char *b=(unsigned char *)base;

            /* over flow or error value
            * [b.....s...(src_len)...]
            * */
            if(0==compress_off_set || compress_off_set>=s-b+src_len)
            return 0;

            /* sub call */
            ret=dns_packet_dynamic_data_read(
                d+dst_off_set,dst_len-dst_off_set,
                b+compress_off_set,(src_len+s-b),
                base);
            if(0==ret)
            return 0;
            return dst_off_set+2; /* only 2 bytes are increase */

        }else{
            return 0;
        }
	}
	/*    03 xx xx xx 04 xx xx xx xx */
	/* -> xx xx xx . xx xx xx xx  */
	return dst_off_set+1;/* last byte is one byte(zero) */

}

static int dns_packet_header_flag_to_flagvar(struct dns_packet_header *packet)
{
    /* hight -> low */
	/* qr(1) opcode(4) aa(1) tc(1) rd(1) | ra(1) zero(3) rcode(4)*/
    packet->flag_qr=0;
    packet->flag_qr= (packet->flag>>15) | packet->flag_qr;
    packet->flag_opcode=0;
    packet->flag_opcode= (packet->flag>>11) | packet->flag_opcode;
    packet->flag_aa=0;
    packet->flag_aa= (packet->flag>>10) | packet->flag_aa;
    packet->flag_tc=0;
    packet->flag_tc= (packet->flag>>9) | packet->flag_qr;
    packet->flag_rd=0;
    packet->flag_rd= (packet->flag>>8) | packet->flag_rd;
    packet->flag_ra=0;
    packet->flag_ra= (packet->flag>>7) | packet->flag_ra;
    packet->flag_zero=0;
    packet->flag_zero= (packet->flag>>4) | packet->flag_zero;
    packet->flag_rcode=0;
    packet->flag_rcode= (packet->flag>>0) | packet->flag_rcode;

    return 0;
}

static int dns_packet_header_flagvar_to_flag(struct dns_packet_header *packet)
{
    /* hight -> low */
	/* qr(1) opcode(4) aa(1) tc(1) rd(1) | ra(1) zero(3) rcode(4)*/
    packet->flag=0;
    uint16_t temp=0;
    temp=packet->flag_qr;
    packet->flag = (temp<<15) | packet->flag;
    temp=packet->flag_opcode;
    packet->flag = (temp<<11) | packet->flag;
    temp=packet->flag_aa;
    packet->flag = (temp<<10) | packet->flag;
    temp=packet->flag_tc;
    packet->flag = (temp<<9) | packet->flag;
    temp=packet->flag_rd;
    packet->flag = (temp<<8) | packet->flag;
    temp=packet->flag_ra;
    packet->flag = (temp<<7) | packet->flag;
    temp=packet->flag_zero;
    packet->flag = (temp<<4) | packet->flag;
    temp=packet->flag_rcode;
    packet->flag = (temp<<0) | packet->flag;

    return 0; 
}

/* dns_packet_header to bytes
 * @Returns 0 - success,-1 - fail 
 * */
static int dns_packet_header_to_bytes(struct dns_packet_header *packet ,void *data,unsigned int data_len)
{

	unsigned int off_set=0;
	unsigned char *p=(unsigned char*)data;

    /* row 1:  0 - 15 */
    /* row 1: 16 - 31 */ 
    uint16_t temp=htons(packet->transaction_id);
	memcpy(p+off_set,&temp,sizeof(packet->transaction_id));
	off_set += sizeof(packet->transaction_id);_DNS_RETURN(off_set>=data_len,0);
    assert(off_set==2);

    dns_packet_header_flagvar_to_flag(packet);
    temp=htons(packet->flag);
	memcpy(p+off_set,&temp,sizeof(packet->flag));
	off_set += sizeof(packet->flag);_DNS_RETURN(off_set>=data_len,0);
    assert(off_set==4); 

    /* row 2: 0 - 15,16 - 31 */
    temp=htons(packet->question_num);
	memcpy(p+off_set,&temp,sizeof(packet->question_num));
	off_set += sizeof(packet->question_num);_DNS_RETURN(off_set>=data_len,0);
    temp=htons(packet->res_record_num);
	memcpy(p+off_set,&temp,sizeof(packet->res_record_num));
	off_set += sizeof(packet->res_record_num);_DNS_RETURN(off_set>=data_len,0);
    assert(off_set==8);

    /* row 3: 0 - 15,16-31 */
    temp=htons(packet->pri_res_record_num);
	memcpy(p+off_set,&temp,sizeof(packet->pri_res_record_num));
	off_set += sizeof(packet->pri_res_record_num);_DNS_RETURN(off_set>=data_len,0);
    temp=packet->extend_res_record_num;
	memcpy(p+off_set,&temp,sizeof(packet->extend_res_record_num));
	off_set += sizeof(packet->extend_res_record_num);_DNS_RETURN(off_set>=data_len,0);
    assert(off_set==12);

    /* dynamic length */
	memcpy(p+off_set,&packet->query_question,packet->query_question_len);
    off_set += packet->query_question_len;_DNS_RETURN(off_set>=data_len,0);

    /*follow with 4 bytpes,0 - 15,16 - 31*/
    temp=htons(packet->query_type);
	memcpy(p+off_set,&temp,sizeof(packet->query_type));
	off_set += sizeof(packet->query_type);_DNS_RETURN(off_set>=data_len,0);
    
    temp=htons(packet->query_class);
	memcpy(p+off_set,&temp,sizeof(packet->query_class));
	off_set += sizeof(packet->query_class);_DNS_RETURN(off_set>=data_len,0);

    print_to_hex(p,off_set);
	return off_set;
}

static void print_dns_record(struct dns_answer_record *record)
{
    printf("record,class:%d,type:%d,size:%d\n%s\n",
            record->answer_class,
           record->answer_type,
           record->answer_size,
           record->answer_value
          );
    if (DNS_TYPE_MX == record -> answer_type)
    {
        printf("mx priority:%d\n",record -> mx_priority); 
    }
}
static void print_dns_packet(struct dns_packet_header *packet)
{
    printf("id:%d,qr:%d,opcode:%d,aa:%d,tc:%d,rd:%d,a:%d,rcode:%d\n",
           packet->transaction_id,
           packet->flag_qr,
           packet->flag_opcode,
           packet->flag_aa,
           packet->flag_tc,
           packet->flag_rd,
           packet->flag_ra,
           packet->flag_rcode
          );
    printf("question_num:%d,resource_record_num:%d,pri_res_record_num:%d,extend_record_num:%d\n",
           packet->question_num,
           packet->res_record_num,
           packet->pri_res_record_num,
           packet->extend_res_record_num
          );
    printf("question_type:%d,question_class:%d:\n%s\n",
           packet->query_type,
           packet->query_class,
           packet->query_question 
          );
    printf("res_record\n");
    for(int i=0;i<packet->res_record_num;i++)
    {
        print_dns_record(&packet->res_record[i]);     
    }
    printf("pri_res_record\n");
    for(int i=0;i<packet->pri_res_record_num;i++)
    {
        print_dns_record(&packet->pri_res_record[i]);     
    }
    printf("extend_res_record\n");
    for(int i=0;i<packet->extend_res_record_num;i++)
    {
        print_dns_record(&packet->extend_res_record[i]);     
    }
}
static void print_to_hex(const void *data,unsigned int data_len)
{

    #ifndef  DEBUG
    return ;
    #endif
    printf("data_len:%d\n",data_len);
    /* print format 
    *  xxxx xxxx  .... ....  xxxx xxxx .... ....
    * */
    printf("\ntcpdump format:\n");
    unsigned char *p=(unsigned char *)data;
    for(unsigned int i=0;i<data_len;i++)
    {
        printf("%02x",p[i]);
        if(i%16==15)
            printf("\n");
        else if(i%2==1)
            printf(" ");
    }
     
    printf("\ndns packet format:\n");
    for(unsigned int i=0;i<data_len;i++)
    {
        printf("%02x",p[i]);
        if(i%4==3)
            printf("\n");
        else if(i%2==1)
            printf(" ");
    }
    printf("\ndns bit format:\n");
    for(unsigned int i=0;i<data_len;i++)
    {
        for(unsigned int j=0;j<8;j++)
        {
            /*0 -  32*/ 
            if((1<<j & p[i] )!=0)
            {
                printf("1"); 
            }else{
                printf("0"); 
            }
        }
        printf(" ");

        /* 4 bytes */
        if(i%4==3)
            printf("\n");
    }

    printf("\n\n");
}

/* parse udp return data into packet_header
 * @Returns size of the packet_header consume ,return 0 while fail 
 * */
static int dns_packet_header_parse(void *data,unsigned int data_len,
                                   struct dns_packet_header *packet)
{
	unsigned int off_set=0;
	unsigned char *p=(unsigned char *)data;
    /* 0-32 */
	memcpy(&packet->transaction_id,p+off_set,sizeof(packet->transaction_id));
	off_set += sizeof(packet->transaction_id);_DNS_RETURN(off_set>=data_len,0);
    packet->transaction_id=ntohs(packet->transaction_id);

    memcpy(&packet->flag,p+off_set,sizeof(packet->flag));
    off_set += sizeof(packet->flag);_DNS_RETURN(off_set>=data_len,0);
    packet->flag=ntohs(packet->flag);
    dns_packet_header_flag_to_flagvar(packet);

    /* 0 - 32 */
	memcpy(&packet->question_num,p+off_set,sizeof(packet->question_num));
	off_set += sizeof(packet->question_num);_DNS_RETURN(off_set>=data_len,0);
    packet->question_num=ntohs(packet->question_num);
    
	memcpy(&packet->res_record_num,p+off_set,sizeof(packet->res_record_num));
	off_set += sizeof(packet->res_record_num);_DNS_RETURN(off_set>=data_len,0);
    packet->res_record_num=ntohs(packet->res_record_num);

    /* 0 - 32 */
	memcpy(&packet->pri_res_record_num,p+off_set,sizeof(packet->pri_res_record_num));
	off_set += sizeof(packet->pri_res_record_num);_DNS_RETURN(off_set>=data_len,0);
    packet->pri_res_record_num=ntohs(packet->pri_res_record_num);

	memcpy(&packet->extend_res_record_num,p+off_set,sizeof(packet->extend_res_record_num));
	off_set += sizeof(packet->extend_res_record_num);_DNS_RETURN(off_set>=data_len,0);
    packet->extend_res_record_num=ntohs(packet->extend_res_record_num);

    /* dynamic data */
	packet->query_question_len = 0;
	int ret=dns_packet_dynamic_data_read(&packet->query_question[0],
                                      sizeof(packet->query_question),
				p+off_set,data_len-off_set,data);
	_DNS_RETURN(0==ret,0);/* have to return something */
	packet->query_question_len=ret;
	off_set+=ret;

    /* 0 - 32 */
    memcpy(&packet->query_type,p+off_set,sizeof(packet->query_type));
    off_set += sizeof(packet->query_type);_DNS_RETURN(off_set>=data_len,0);
    packet->query_type=ntohs(packet->query_type);

    memcpy(&packet->query_class,p+off_set,sizeof(packet->query_class));
    off_set += sizeof(packet->query_class);_DNS_RETURN(off_set>=data_len,0);
    packet->query_class=ntohs(packet->query_class);


    /* parse resource_record_num resource record */

    for(int i=0;i< (packet->res_record_num);i++)
    {
        ret=dns_answer_record_parse(p+off_set,data_len-off_set,data,
                                   &packet->res_record[i]);
        if(ret==0)
        {
            _ERROR("res_record parse fail\n");
            return 0;
        }
        off_set += ret;
        
    }

    /* parse pri_res_record_num privileges resource record */

    for(int i=0;i< (packet->pri_res_record_num);i++)
    {
        ret=dns_answer_record_parse(p+off_set,data_len-off_set,data,
                                   &packet->pri_res_record[i]);
        if(ret==0)
        {
            
            _ERROR("res_record parse fail\n");
            return 0;
        }
        off_set += ret;
    }

    /* parse extend_res_record_num extend resource record */

    for(int i=0;i< (packet->extend_res_record_num);i++)
    {
        ret=dns_answer_record_parse(p+off_set,data_len-off_set,data,
                                   &packet->extend_res_record[i]);

        if(ret==0)
        {
            _ERROR("res_record parse fail\n");
            return 0;
        }
        off_set += ret;

    }

    return off_set;
}

/* parse one record from data,return read_off_set of data,read data[0,read_off_set) 
* return format: 
 *              192.168.1.108
 *              0123456789...
 * */
static int dns_answer_record_parse(void *data,unsigned int data_len,
                                   void *base/*dns packet base address*/,
                                   struct dns_answer_record *record)
{
    memset(record,0,sizeof(struct dns_answer_record));
    /* 0 - 32
     * domain name(dynamic data)
     * answer_type  |   answer_class
     *      time_to_live   
     * answer_size  | length of answer_size ..
     * ....
     *
     * */
	unsigned int off_set =0;
    unsigned char *p=(unsigned char*)data;
	record->answer_name_len=0;
	unsigned int ret=dns_packet_dynamic_data_read(&record->answer_name[0],
                                      sizeof(record->answer_name),
				data,data_len,base);
	_DNS_RETURN(0==ret,0);
	record->answer_name_len = ret;
	off_set += ret;

    /* 0 - 32*/
	_DNS_RETURN(off_set + sizeof(record->answer_type)>=data_len,0);
	memcpy(&record->answer_type,p+off_set,sizeof(record->answer_type));
	off_set += sizeof(record->answer_type);
    record->answer_type=ntohs(record->answer_type);

	_DNS_RETURN(off_set + sizeof(record->answer_class)>=data_len,0);
	memcpy(&record->answer_class,p+off_set,sizeof(record->answer_class));
	off_set += sizeof(record->answer_class);
    record->answer_class=ntohs(record->answer_class);

    /* 0 - 32 */
	_DNS_RETURN(off_set + sizeof(record->time_to_live)>=data_len,0);
	memcpy(&record->time_to_live,p+off_set,sizeof(record->time_to_live));
	off_set += sizeof(record->time_to_live);
    record->time_to_live=ntohs(record->time_to_live);

    /* 0 - 16 */
	_DNS_RETURN(off_set + sizeof(record->answer_size)>=data_len,0);
	memcpy(&record->answer_size,p+off_set,sizeof(record->answer_size));
	off_set += sizeof(record->answer_size);
    record->answer_size=ntohs(record->answer_size);

    /* record->answer_size length char */
    _DNS_RETURN(off_set + record->answer_size>data_len,0);

    switch(record->answer_type)
    {
        case DNS_TYPE_A:
        {
            int si= 4 * record->answer_size;
            memcpy(&record->answer_value[0] + si,p+off_set,record->answer_size);
            off_set += record->answer_size;

            /*192/168/1/108 to 192.168.1.1 format */
            
            int ip_off_set=0;
            for(int i=0;i<record->answer_size;i++)
            {
                unsigned char v=record->answer_value[si++];
                if(v/100)
                {
                    record->answer_value[ip_off_set++]='0'+v/100;
                }
                if(v/10)
                {
                    record->answer_value[ip_off_set++]='0'+(v/10)%10;
                }
                record->answer_value[ip_off_set++]='0'+v%10;
                if(i!=(record->answer_size-1))
                    record->answer_value[ip_off_set++]='.';
            }
            record->answer_value[ip_off_set]='\0';
        }break;
        case DNS_TYPE_MX:
        {
            /* first two bytes is priority */ 
            uint16_t mx_priority=0;
            _DNS_RETURN(off_set + sizeof(mx_priority) > data_len,0);
            memcpy(&mx_priority,p+off_set,sizeof(mx_priority));
            mx_priority = ntohs(mx_priority);
            off_set += sizeof(mx_priority); 
            record -> mx_priority = mx_priority;

            /* div 2 bytes priority */
            record -> answer_size -= sizeof(mx_priority);
            _DNS_RETURN(off_set + record-> answer_size > data_len,0);  
            ret=dns_packet_dynamic_data_read(&record->answer_value,
                                             sizeof(record->answer_value),
                                             p+off_set,data_len-off_set,
                                             base);
           	off_set += record->answer_size;

        }break;
        default:
        {
            /* use dynamic read function to parse data*/

            ret=dns_packet_dynamic_data_read(&record->answer_value,
                                             sizeof(record->answer_value),
                                             p+off_set,data_len-off_set,
                                             base);
           	off_set += record->answer_size;

        };
    }
        
	return off_set;
}

/* socket part  */
static int sockaddr_init(struct sockaddr_in * sin, int port, const char *ip)
{
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    long s_addr_long;
    if (NULL == ip)
    {
        s_addr_long = htonl(0);
    }
    else
    {
        s_addr_long = inet_addr(ip);
    }

    if (s_addr_long == -1)
    {
        _ERROR("fail to create s_addr_long");
        return -1;
    }

    sin->sin_addr.s_addr = s_addr_long;
    bzero(&sin->sin_zero, 8);
    return 0;
}


static int dns_udp_query(int clientfd,struct sockaddr * sin,
                         const char *query_name,int dns_type,
                        struct dns_packet_header *dns_packet)
{
    int ret;
    char buf[MAX_PACKET_SIZE];
	char dns_packet_buf[MAX_PACKET_SIZE];

    /*build packet*/
	struct dns_packet_header packet;
    memset(&packet,0,sizeof(packet));
    {
        struct timeval tv;
        gettimeofday(&tv,NULL);
        srand(tv.tv_usec);
        packet.transaction_id=rand();  
        packet.flag_qr=0;
        packet.flag_opcode=0;
        packet.flag_rd=1;
        packet.question_num=1;
        /* question */
        ret=dns_packet_host_to_dynamic_data(&packet.query_question[0],
                                            sizeof(packet.query_question)
                                            ,query_name);
        if(ret<=0)
        return -1;
        
        packet.query_type=dns_type;
        packet.query_class=1; /* internet address */
        packet.query_question_len=ret;
    }

	/* send dns packet by udp */
	ret=dns_packet_header_to_bytes(&packet,buf,sizeof(buf));
	if(ret==0)
	  return -1;

	socklen_t dns_server_addr_len=sizeof(*sin);
	ret=sendto(clientfd,buf,ret,0,
				sin,
				dns_server_addr_len);
	if(0>=ret)
	{
		_ERROR("send udp request to dns server fail\n");
		return -1;
	}
		
     /* recv  dns packet return. */
	unsigned int dns_packet_buf_read_len=0;
	unsigned int dns_packet_buf_len=sizeof(dns_packet_buf);
	memset(dns_packet_buf,0,sizeof(dns_packet_buf));

	for(;;)
	{
        socklen_t sl=sizeof(struct sockaddr);
        struct sockaddr_in recv_sin;
		ret=recvfrom(clientfd,buf,sizeof(buf),0,
					(struct sockaddr*)&recv_sin,&sl);

		/* no read return or timeout */
		if(ret<=0  )
		  break;
		if(ret+dns_packet_buf_read_len>sizeof(dns_packet_buf))
		{
			/*over flow */
			memcpy(&dns_packet_buf[0]+dns_packet_buf_read_len,buf,
						(dns_packet_buf_len - dns_packet_buf_read_len));
			dns_packet_buf_read_len = dns_packet_buf_len;
			break;
		}else{
			memcpy(&dns_packet_buf[0]+dns_packet_buf_read_len,buf,
						ret);
			dns_packet_buf_read_len += ret;
            /* only read one packet */
            break;
		}
	}
	if(dns_packet_buf_read_len==0)
	  return -1;

	/* parse  */

	ret=dns_packet_header_parse(dns_packet_buf,dns_packet_buf_read_len,dns_packet);
	if(ret==0)
	{
		_ERROR("dns_packet_header_parse fail\n");	
		return -1;
	}

    /* check return state */

    if(dns_packet->transaction_id != packet.transaction_id /* transaction_id not right */
        ||
       dns_packet->flag_rcode != 0 /* unnormal return code */
      )
        return -1;

    return 0;
		
}

/*
 * domaim_name , if success,value store in data  */
int dns_query(const char *domain_name,char *data,int len,int dns_type=DNS_TYPE_A,
             int print=0)
{

	/* query for udp. fetch each items.*/

    int clientfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientfd < 0)
    {
		_ERROR("socket() fail \n");
        return -1;
    }

    char (opts[])[3] =
    {
        {SO_REUSEADDR, 1, 1}
    };

    int ret;
    int opt_name;
    int opt_value;
    int opt_len = sizeof (opts) / sizeof (void *);
    for (int i = 0; i < opt_len; i++)
    {
        opt_name = opts[i][0];
        opt_value = opts[i][1];
        ret =
        setsockopt(clientfd, SOL_SOCKET, opt_name, &(opt_value),
                   sizeof (opt_value));
		if(0!=ret)
		{
			_ERROR("setsockopt fail \n");
			return -1;
		}
    }

    
    struct timeval tv;
	tv.tv_sec = 1; /* timeout 3 seconds */
    tv.tv_usec = 0;
	ret = setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &tv,
				sizeof (struct timeval));
	if (ret)
    {
		_ERROR("SO_SNDTIMEO set fail\n");
        return -1;
    }
    
    ret =setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv,
               sizeof (struct timeval));
    if (ret)
    {
        _ERROR("setsockopt SO_RCVTIMEO FAIL\n");
        return -1;
    }

	struct sockaddr_in sin;
    if (sockaddr_init(&sin, DNS_SERVER_PORT, DNS_SERVER_IP))
    {
        _ERROR("sockaddr init fail \n");
        return -1;
    }
    
    struct dns_packet_header dns_packet;
    ret=dns_udp_query(clientfd,(struct sockaddr*)&sin,
                      domain_name,dns_type,&dns_packet);
    if(ret)
        return -1;

    /* only return one res_record into data */
    
    if(dns_packet.res_record_num>0)
    {
        snprintf(data,len,"%s",dns_packet.res_record[0].answer_value); 
    }

    /* printf test */

    if(print)
    print_dns_packet(&dns_packet);

    /* copy data to caller */

	ret = close(clientfd);
	return 0;
}

#ifdef TEST_DNS_UTIL
int main(int argc,char **argv)
{

    int need_count=0;
    int dns_type=DNS_TYPE_A;
    char host[256];
    char data[256];

    char ch;  
    while ((ch = getopt(argc,argv,"h:t:"))!=-1)  
    {  
        switch(ch)  
        {  
            case 'h':  
            need_count++;
            strcpy(host,optarg);
            break;  
            case 't':  
            dns_type= atoi(optarg);
            break;  
            default:  
            {
                goto End;
            }
        }  
    }  
    
    if(need_count==1)
    {
        dns_query(host,data,sizeof(data),dns_type,1);
        printf("dns_query ret %s\n",data);
        return 0;
    }



    End:
    printf("usage: -h [host name] -t [dns type] \
           \ndns type:1 - A ,5 - CNAME,15 - MX ...\n");  
    return -1;
}

#endif 
