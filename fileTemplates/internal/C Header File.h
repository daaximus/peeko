#parse("C File Header.h")

#set($HeaderName = $NAME.toUpperCase())
#[[#ifndef]]# _${HeaderName}_H_
#[[#define]]# _${HeaderName}_H_

#[[#endif]]# // _${HeaderName}_H_
