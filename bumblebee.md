**Background** : This is an analysis of an unpacked bumblebee. This is meant to be a little reversing tutorial, as well as a demonstration of some basic reverse engineering and research skills I learned. 
The unpacked sample was downloaded from malware bazaar. I found the hash through this [article](https://bin.re/blog/the-dga-of-bumblebee/)

Bumblebee has two exports. As it is a dll, it's exports important because they contain the main functions of the malware.
We are going to look at the export starting at ```start	0000000140057D2C	[main entry]```
This is the 'main' function of the malware.  

![image1](/resources/bumblebee/image1.png)

![image2](/resources/bumblebee/image2.png)

When we scroll into the main function a little, we start noticing some intersting things. 
Let's start with this string:
![image3](/resources/bumblebee/image3.png)

I know that bumblebee uses RC4 encryption from two sources. One, from reading about the malware from articles like [this](https://www.proofpoint.com/us/blog/threat-insight/bumblebee-is-still-transforming) and two, from Flare's capa explorer plugin which indicates it found a pattern matching RC4 encryption. 

![image4](/resources/bumblebee/image4.png)

Shortly after this interesting string, a function call is made that takes another intersting string as an arugment

![alt text](/resources/bumblebee/image5.png)

![alt text](/resources/bumblebee/image-1.png)
here we get the hex representation of the second interesting string

![alt text](/resources/bumblebee/image-2.png)

If we use the initial interesting string as a passphrase for a RC4 encryption algorithm to decrypt the strange jumbled up encrypted looking string, we get an interesting output

![alt text](/resources/bumblebee/image-3.png)

The output reads `lnk1` 
This indicates that this version of bumblebee is being distributed via lnk email attachments. Furthermore, it possibly indicates that the authors of bumblebee set their versioning to indicate the initial vector of infection. 

Shortly after, the malware generates hashes and passes them to the `CreateEventW` API call

![alt text](/resources/bumblebee/image7.png)

`CreateEventW` is used to ensure the malware isn't already running, hence the check shown in the screenshot against error code 183 or `ERROR_ALREADY_EXISTS`

Following this we see some strings indicating the malware is collecting information about the infected host. Specifically username and Domain name.
![alt text](/resources/bumblebee/image8.png)
![alt text](/resources/bumblebee/image9.png)

Next we move onto address `0014001085E` 
Here a function is called that does various interesting things.

First, an API call to GetSpecialFolderPath with an interesting array of paths
![alt text](/resources/bumblebee/image10.png)

Then a function is called that generates a random executable name. This is likely to avoid basic file-name based detection
![alt text](/resources/bumblebee/image11.png)

We then enter a subroutine that gathers information about the infected host.
![alt text](/resources/bumblebee/image12.png)

Bumblebee then loops through it's own threads using `CreateToolhelp32Snapshot`


