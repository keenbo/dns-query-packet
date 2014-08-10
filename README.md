#### DNS query packet for c 
>  support DNS A record / MX record query       


#### usage  
>  for test (run shell): make run_dns    
> for api call: #include "util_dns.h"       
> then  call method:     
>        int dns_query(const char *host,char *data,int data_len,int dns_type)       


####  Example , run in my bash    
`$ make run_dns `

`$ return below` 

id:46300,qr:1,opcode:0,aa:0,tc:1,rd:1,a:1,rcode:0   
question_num:1,resource_record_num:1,pri_res_record_num:0,extend_record_num:0   
question_type:1,question_class:1:   
www.qq.com   
res_record  
record,class:1,type:1,size:4  
180.96.86.192   
pri_res_record  
extend_res_record  
dns_query ret 180.96.86.192

