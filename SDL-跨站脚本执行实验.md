# SDL-跨站脚本执行实验

---
## 实验背景知识：
- 跨站脚本执行（XSS）：Web应用程序在将数据输出到网页的时候存在问题，导致攻击者可以将构造的恶意数据显示在页面的漏洞。
- 跨站脚本执行分类：
    - 非持久型XSS：非持久型XSS（Non-persistent）又叫做反射XSS（Reflect XSS），它是指那些浏览器每次都要在参数中提交恶意数据才能触发的跨站脚本漏洞。
    - 持久型XSS：持久型XSS（Persistent）又叫做存储XSS（Stored XSS），与非持久型XSS相反，它是指通过提交恶意数据到存储器（比如数据库、文本文件等），Web应用程序输出的时候是从存储器中读出恶意数据输出到页面的一类跨站脚本漏洞。
## 实验环境：
- WebGoat
- 非持久型XSS
## 实验过程：
- 实验环境搭建
    - 先在kali上安装docker和docker compose；
    - 然后按照下图所示搭建即可。 
    ![利用口令搭建漏洞练习环境][1]
    ![环境搭建中][2]
    - 搭建完成，登录webgoat  
    ![ps查看搭建成功][3]
    ![登录webgoat][4]
- 进行XSS漏洞练习训练
    - 以Tom的身份登录，点击ViewProfile按钮，在street一栏输入`<script>alert('hacked')</script>`,然后点击UpdateProfile按钮，页面显示‘hacked’：  
    ![tom开始][5]
    ![tom非法代码][6] 
    ![tom成功][7]
    - 以Larry身份登录，点击‘SearchStaff’，在搜索框添加代码`<script>alert('dangerous')</script>`,最后点击‘FindProfile’按钮:  
    ![larry-开始][8]  
    ![larry-成功][9]
## 实验总结：
- XSS漏洞的预防方法：
    - 编写安全的代码；
    - 安全的处理数据；
    - 提高攻击门槛。
## 实验参考资料：
- https://wenku.baidu.com/view/0d9de30e905f804d2b160b4e767f5acfa1c783d7.html?pn=1（webgoat中文手册）；
- https://blog.csdn.net/lifushan123/article/details/45226437（跨站脚本攻击（XSS）的原理、防范和处理方法）。


  [1]: https://s2.ax1x.com/2019/11/22/M75QTe.jpg
  [2]: https://s2.ax1x.com/2019/11/22/M75nOK.jpg
  [3]: https://s2.ax1x.com/2019/11/22/M753Yd.jpg
  [4]: https://s2.ax1x.com/2019/11/22/M75MwD.jpg
  [5]: https://s2.ax1x.com/2019/11/24/MLUKvd.jpg
  [6]: https://s2.ax1x.com/2019/11/24/MLUugH.jpg
  [7]: https://s2.ax1x.com/2019/11/24/MLUGUf.jpg
  [8]: https://s2.ax1x.com/2019/11/24/MLUlDI.jpg
  [9]: https://s2.ax1x.com/2019/11/24/MLUQKA.jpg