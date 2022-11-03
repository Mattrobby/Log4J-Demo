# Log4J-Demo

## What is Log4J? 

- A logging tool, written in Java, that is commonly used in many applications across the internet [^4]

## Notes

- Originally discovered in Minecraft which used this tool to keep logs 
- Allowed an attacher a `JNDI` command and if that is passed to the logger it would give the hacker *remote code execution* 
- It could easily be put in a script that mass scans the internet and finds servers vulnerable to this and then exploits them
  - There are there were several bonnets of computers doing exactly that while the exploit was live [^3] 

- Got a 10/10 score as a vulnerability (this is very rare) 

### Fix

- Disables JNDI by default (a logger resolving JDAP addresses by default is not a good idea)
- Completely removes support for Messages lookups (this is to fix [`CVE-2021-45046`](https://nvd.nist.gov/vuln/detail/CVE-2021-45046))

### Are you Vulnerable? 

- https://github.com/NCSC-NL/log4shell

[^1]: [Office Log4J Patch Page](https://logging.apache.org/log4j/2.x/security.html)
[^2]: [CVE Page](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
[^4]: [Log4J Vulnerabilities Continue To Wreak Havoc on the Internet - Mental Outlaw](https://www.youtube.com/watch?v=QhW5csA51Bs)
[^3]: [Ten families of malicious samples are spreading using the Log4j2 vulnerability Now](https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/) 
