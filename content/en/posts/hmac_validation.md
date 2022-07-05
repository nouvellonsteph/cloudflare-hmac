---
title: "Validating HMAC with Cloudflare"
date: 2022-07-05T11:03:34+02:00
draft: false
---

The link below is valid forever for the purpose of the test. The MAC message is a HMAC (sha1) signature of the path of the request.

<https://>


The workers script running on your zone must be the following

```
addEventListener('fetch', event => {
  event.respondWith(fetchAndLog(event.request))
})
async function fetchAndLog(request) {

  let url = new URL(request.url)

  if (url.protocol == "http:") {
    url.protocol = 'https:'
    return Response.redirect(url.href, 301)
  }
  
  if (url.searchParams.get('verify') && url.searchParams.get('verify').match(/^\d.*-.*$/)) {
    const encoder = new TextEncoder()
    const token = url.searchParams.get('verify').split('-')[1]
    const timestamp = url.searchParams.get('verify').split('-')[0]
    const expiration = 60
    let verify

    let key = await crypto.subtle.importKey(
    "raw", encoder.encode("cloudflare"),
    {name: "HMAC", hash: {name: "SHA-256"}},
    false, [ "verify" ]
    )
  
    try {
      verify = await crypto.subtle.verify(
      "HMAC", key,
      byteStringToUint8Array(atob(token)),
      encoder.encode(url.pathname + timestamp)
      )
    }
    catch (err) {
      return new Response('TOKEN VERIFICATION FAILED', { status: 403 })
    }
    
    if (!verify){
      return new Response('INVALID TOKEN', { status: 403 })
    }
    else if (Math.floor(Date.now()/ 1000) - timestamp > expiration){
      return new Response('TOKEN EXPIRED', { status: 403 })
    }
    return await fetch(request)
  } 
  return new Response('NON VALID TOKEN PROVIDED', { status: 403 })
}

function byteStringToUint8Array(byteString) {
  const ui = new Uint8Array(byteString.length)
  for (let i = 0; i < byteString.length; ++i) {
    ui[i] = byteString.charCodeAt(i)
  }
  return ui
}
```

