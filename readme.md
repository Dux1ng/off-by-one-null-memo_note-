## off-by-one-null
一种uaf, 能通过溢出一个字节'\x00'，完成地址泄露，有限地址读写能力....一句话说明白有点复杂，也有可能不严谨...
## 题目分析
![menu](img/menu.PNG)
### 漏洞点
在new的时候读内容的时候，最后多写了一个\x00
![vuln](img/vuln.PNG)
## 利用思路
### 泄露libc基址（用memo_note举例）
1.

### 1.
