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
在c8~RtlMinimalBarrier的数据结尾总是以ret为结尾    
此ret为RtlMinimalBarrier函数尾部代码    

![pg](https://github.com/zhuhuibeishadiao/PatchGuardResearch/blob/master/doc/pg.PNG)    
首先我们通过pgContext的前4个函数进行内存碰撞，得到pgContext的首地址(注意,在1809 rs5版本中,rcx的值改变了)    
具体的细节待全部完成后更新.    

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
[mengwuji : windows10 patchguard绕过讨论]    
[mengwuji : 绕过windows10 patchguard原理与实现]    
[9176324 : Shark](https://github.com/9176324/Shark)  
[DarthTon : Blackbone](https://github.com/DarthTon/Blackbone)    
[Mr Guo]    


