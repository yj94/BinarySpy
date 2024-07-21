# BinarySpy

> A tool for manual or automatic patch shellcode into binary file Oder to bypass AV.
> 一个手动或自动patch shellcode到二进制文件的工具

## 1.GUI

![1721527665615](image/README/1721527665615.png)

## 2.使用方法

+ 待修改的pe文件路径就是要被patch shellcode的pe文件
+ VA
  + 手动:要修改PE文件的VA就是该pe文件的要被patch虚拟地址
  + 自动:无需填写VA
+ 待覆盖的.text文件就是shellcode的text段
  + 内容可自动提取或者选择非.exe结尾的文件作为.text文件
+ 最后,点击执行即可
+ 注意:仅限于x64的程序patch且语言为C,其他语言适配请等更新
