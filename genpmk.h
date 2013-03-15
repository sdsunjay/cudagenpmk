int IsBlank(char *s)  
{
         
   int len, i;
   if (s == NULL) {
      return (1);
   }
            
   len = strlen(s);
      
   if (len == 0) {
      return (1);
   }
         
   for (i = 0; i < len; i++) {
      if (s[i] != ' ') {   
         return (0);
      }
   }
   return (0);
}

struct hashdb_head {
   uint32_t magic;
   uint8_t reserved1[3];
   uint8_t ssidlen;
   uint8_t ssid[32];
};
struct user_opt {
   char ssid[256];
   char dictfile[256];
   char pcapfile[256];
   char hashfile[256];
   u8 nonstrict;
    u8 checkonly;
   u8 verbose;
    u8 unused;
};
struct hashdb_rec {
   uint8_t rec_size;
   char *word;
   uint8_t pmk[32];
} __attribute__ ((packed));

#define MAXPASSLEN 64

