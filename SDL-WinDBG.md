# SDL-WinDBG

---
## 实验目的：
修改 32 位 Windows 7 下的计算器的显示过程，使得当你输入的内容是特定数字如 "999" 的时候通过调试器脚本自动改为 "666"。
## 实验环境：
windows7+WnDBG
## 实验过程：
1. 由于windows7系统版本过低，需要前往[windows 7 SDK在线安装程序][1]下载SDK文件；
2. 新建windows7虚拟机，进入计算机，点击VirtualBox Guest Additions安装win7增强功能；
3. 虚拟机设备——共享文件夹——设置共享文件夹——读入第一步下载的SDK文件——WinDBG安装成功；
4. 在win7桌面新建command.txt文本，写入以下内容：
```
as /mu content poi(esp+8)
.block{.if($scmp("${content}","999")==0){ezu poi(esp+8) "666";}.else{.echo content}}
g

```

5. 打开计算器，进入WinDBG选择: File-Attach to a Process-calc.exe；
  ![01][2]
6. 设置断点调试：`bu user32!SetWindowTextW "$><C:\\Users\\root\\Desktop\\command.txt"`;
  ![03][3]
7. `g`后在计算器界面输入999，显示666。
  ![04][4]
  ![成功][5]
## 实验总结：
- 注意先查找自己计算器里输入内容的偏移地址，我的电脑是esp+8，再使用poi函数访问括号里地址的对应值。


  [1]: https://www.microsoft.com/en-us/download/details.aspx?id=8279
  [2]: https://s2.ax1x.com/2019/12/13/QcX6Qs.jpg
  [3]: https://s2.ax1x.com/2019/12/13/QcXrWQ.jpg
  [4]: https://s2.ax1x.com/2019/12/13/QcjC6A.jpg
  [5]: https://s2.ax1x.com/2019/12/13/QcjPOI.jpg