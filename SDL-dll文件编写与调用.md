# SDL-dll文件编写与调用


---

## 实验目的：
编写生成dll文件，并使用exe文件调用生成的dll文件；
## 实验环境：
Virtual Studio 2017
## 实验过程：
#### dll文件的生成：
- 新建项目dll-edit，在源文件中添加base.c和exp.def两个文件，写入以下代码：
```
//base.c
#include <Windows.h>
int internal_function()
{
	return 0;
}
int lib_function(char *msg)
{
	MessageBox(0, "msg from base lib", msg, MB_OK);
	return 0;
}
//exp.def
LIBRARY baseLib
EXPORTS
    lib_function
```
- 打开vs对应命令提示符，进入dll-edit文件目录下，进行以下操作：
```
cl.exe /c base.c //把base.c文件编译成为obj文件
link base.obj User32.lib /dll /def:exp.def //把obj文件和lib文件链接为新的dll和lib文件
dumpbin /exports baseLib.dll //使用dumpbin命令验证生成的dll文件，发现有.c文件中定义的lib_function函数，dll文件生成成功
```
![dll成功][1]
#### 新建exe文件调用dll文件
- 新建项目app，在源文件中新建app.c文件，写入以下代码：
```
//app.c
int main()
{
	lib_function("call a dll");
	return 0;
}
```
- 使用命令行编译链接生成app.exe（指定路径），再复制dll路径，运行app.exe成功调用dll：
```
cl.exe /c app.c //把app.c文件编译成obj文件
link app.obj ..\dll-edit\base.lib /out:app.exe //使用前一个目录下生成的lib文件链接生成exe文件
dumpbin /imports app.exe //看导出表
copy ..\dll-edit\baseLib.dll //将dll复制到app项目目录下，便于app.exe文件执行时可直接调用上述生成的dll文件
app.exe //执行exe文件，发现其调用了dll文件中的函数，出现了弹框，实验成功。
```
![exe调用dll成功][2]


  [1]: https://s2.ax1x.com/2019/12/18/Q71sun.jpg
  [2]: https://s2.ax1x.com/2019/12/18/Q71Bcj.jpg