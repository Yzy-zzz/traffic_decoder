**生成会话秘钥代码**

+ 输入master_key，client random、server random
+ 输入套件类型



**各文件说明**

+ test.cpp——main主函数所在文件 ，可以输入随机数和套件类型
+ my_utils.h——一些具体的函数实现
+ my_typedef.h——一些宏定义和类型声明
+ ssl_debug_file.h——最后输出的结果所在的文件



**函数逻辑**

+ main函数（其中给定一些输入）
  + 进入generate_material函数（根据不同的套件类型来确定输出长度的大小）
    + 再进入prf函数（这里根据不同的协议类型选择不同的hash函数，有ssl3_hash、tls_hash、tls12_hash）
      + 各个具体的哈希函数用来生成key

