#include "_head.h"

#define DNS_NAME_SIZE 2048
#define MAX_DNS_SIZE 10
#define DNS_RECORD_RES  0
#define DNS_RECORD_PRI_RES  2
#define DNS_RECORD_EXT_RES 3


typedef struct dns_answer_record{
    int record_type;/* DNS_RECORD_RES DNS_RECORD_PRI_RES DNS_RECORD_EXT_RES*/
    char answer_name[DNS_NAME_SIZE];
    unsigned int answer_name_len;
	uint16_t answer_type;
	uint16_t answer_class;
	uint32_t time_to_live;
	uint16_t answer_size;
    char answer_value[65536];/* 2^16 = 65536 */

	/* extend part */
	uint16_t mx_priority;
}dns_answer_record_t;



typedef struct dns_packet_header{

    /*   
     *   DNS packet format
     0                 15 |  16               32     
        transaction_id    |         flag...
        question_num      |    res_record_num
      pri_res_record_num  |   extend_res_record_num
      -- query questions, length = question_num --
          query question [n=0-63] n char...[n1=0-63] n1 char... end with 0(char)
          query_type      |      query_class 
      -- res_record_answer, length = res_record_num --
      [n=0-63] n char...[n1=0-63] n1 char... end with 0(char)
           query_type      |      query_class 
                  time     to   live(seconds) 2^32 
        answer_size(2^16)  |  follow with answer(answer_size long) 
      -- pri_res_record_answer and extend_res_record like above
         res_record_answer...
     * */

    /* dns transaction id 
    * dns server return the same value to client */
	uint16_t transaction_id;
	
	uint16_t flag;

	/*
	   QR：0表示查询报文，1表示响应报文
	   Opcode：通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）。
	   AA：表示授权回答（authoritative answer）.
	   TC：表示可截断的（truncated）
	   RD：表示期望递归
	   RA：表示可用递归
	   随后3bit必须为0
	   Rcode：返回码，通常为0（没有差错）和3（名字差错）
	   后面4个16bit字段说明最后4个变长字段中包含的条目数。
	   */
	/* qr opcode(4) aa tc rd | ra zero(3) rcode(4)*/
    unsigned int flag_qr:1;
    unsigned int flag_opcode:4;
    unsigned int flag_aa:1;
    unsigned int flag_tc:1; 
    unsigned int flag_rd:1;

    unsigned int flag_ra:1;
    unsigned int flag_zero:3;
	unsigned int flag_rcode:4;
	

    /* question_num */
	uint16_t question_num;
	uint16_t res_record_num;
	/* grant privileges resource record num */
	uint16_t pri_res_record_num;
	uint16_t extend_res_record_num;

    /* query question info */ 
    char query_question[DNS_NAME_SIZE]; /* assume max is 2048*/
    unsigned int query_question_len; 

	uint16_t query_type;
	uint16_t query_class;
	
	struct dns_answer_record res_record[MAX_DNS_SIZE];
	struct dns_answer_record pri_res_record[MAX_DNS_SIZE];
	struct dns_answer_record extend_res_record[MAX_DNS_SIZE];

}dns_packet_header_t;

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13 
#define DNS_TYPE_MX 15 

/*
 *   dns response type:
 *   A   -   1
 *   NS  -   2
 *   CName   -   5
 *	 pTR     -   12 
 *	 HINFO   -   13 (
 *	 MX      -   15 
 *	 AXFR    -   252
 *   * or ANY   -   255
 *
 *
 * 
 *
 *
 * */
