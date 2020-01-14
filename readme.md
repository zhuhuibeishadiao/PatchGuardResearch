# win10 PatchGuard 动态解密(btc版本)  

**此项目能够动态解密pgContext的一部分**  
pgContext是由多个部分组成    
0 - 0xc8是一部分    
0 - RtlMinimalBarrier的偏移是一部分(在1803上,此偏移为0x1A2A8)    
RtlMinimalBarrier - RtlMinimalBarrier+0xA00 是明文    
0x1A2A8+0xA00 - ....是另一部加密的Context    
具体可以看doc中的dump.log    
此项目解密0 - RtlMinimalBarrier的偏移    
对于攻破PatchGuard,这段偏移中的数据已经足够    

## 原理

在通过观察dump.log已经结合0x109的蓝屏文件,可以得出一个信息    
在c8~RtlMinimalBarrier的数据结尾大部分以ret为结尾    
此ret为RtlMinimalBarrier函数尾部代码    

![pg](https://github.com/zhuhuibeishadiao/PatchGuardResearch/blob/master/doc/pg.PNG)    
首先我们通过pgContext的前2个函数进行内存碰撞，得到pgContext的首地址(注意,在1809 rs5版本中,rcx的值改变了)
然后通过找到未加密的RtlMinimalBarrier的ret,进行解密.
注意pgContext可能存在多个,使用上面的方法可能不会得到全部的pgContext  

最新的发现:  
pgContext可能不会由ret结尾  
在经过多次实验后得出以下：  
1.pgContext可能是全加密的(1909之前概率较低 1909极大概率出现)  
2.pgContext可能会申请NonPagedPoolSession的内存(调试时一部分Context已经解密 推测此时pg正在进行解密)  
3.pgContext结尾可能是以下三种情况  
	结尾为c3  
	结尾为RtlMinimalBarrier的最后几个字节(目前仅在1909实验发现过)  
	结果为密文(RtlMinimalBarrier整个函数的密文)  
4.1909部分碰撞出来的pgContext都已经是全解密后的,推测...  

在RtlMinimalBarrier后面跟着的大概是这么一个结构  
  
xxxxxxxxxxxxxxxxx  上面三种情况的其中一种  
ffffa38a`2cf1dc45  00000000`00000000  
ffffa38a`2cf1dc4d  fffff806`20cbe8c7 nt!ExQueueWorkItem+0x7  
ffffa38a`2cf1dc55  56d15c8b`00000010  
ffffa38a`2cf1dc5d  00000000`00000001  
ffffa38a`2cf1dc65  00000000`00000000  
ffffa38a`2cf1dc6d  00000000`00000000  
ffffa38a`2cf1dc75  00000000`00000000  
ffffa38a`2cf1dc7d  fffff806`20cbe8d7 nt!ExQueueWorkItem+0x17  
ffffa38a`2cf1dc85  2ecc050e`0000008a  
   
c3下面的0可能是用于对齐?  
            剩下的结构体  
            _struct xxxxx  
            {
                PVOID routine;  
                ULONG checksum?;  
                ULONG routineCodeSize;  
                PVOID unknow;(一直为1)  
                PVOID Fileds[3];  
            }  
  

## 关于调试PatchGuard  
双机调试：开启调试模式后,重启,不要开windbg,等待开机界面圈圈出现,让它转一会,等它转一会后突然卡住不转动,数1-2秒开启windbg即可.  

## 此项目暂不攻破PatchGuard    
其实,有了解密之后攻破已经不是问题了.    
只是目前重心不在于攻破,见谅.  

## 目录说明  
doc:一些资料整理  
helper:用于辅助dump和校验pgContext  
PatchGuard:主逻辑  

## 感谢
[tandasat : some-tips-to-analyze-patchguard](http://standa-note.blogspot.com/2015/10/some-tips-to-analyze-patchguard.html)  
[tandasat : findpg](https://github.com/tandasat/findpg)  
[tandasat : PgResarch](https://github.com/tandasat/PgResarch)  
mengwuji : windows10 patchguard绕过讨论      
mengwuji : 绕过windows10 patchguard原理与实现      
[9176324 : Shark](https://github.com/9176324/Shark)  
[DarthTon : Blackbone](https://github.com/DarthTon/Blackbone)    
Mr Guo      


