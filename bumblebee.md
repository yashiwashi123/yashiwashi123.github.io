**Background** : This is an analysis of an unpacked bumblebee. This is meant to be a little reversing tutorial, as well as a demonstration of some basic reverse engineering and research skills I learned. 
The unpacked sample was downloaded from malware bazaar. I found the hash through this [article](https://bin.re/blog/the-dga-of-bumblebee/)

Bumblebee has two exports. As it is a dll, it's exports important because they contain the main functions of the malware.
We are going to look at the export starting at ```start	0000000140057D2C	[main entry]```
This is the 'main' function of the malware.  

![image1](/resources/bumblebee/image1.png)

![image2](/resources/bumblebee/image2.png)

When we scroll into the main function a little, we start noticing some intersting things. 
Let's start with this string:
![alt text](/resources/bumblebee/image3.png)
