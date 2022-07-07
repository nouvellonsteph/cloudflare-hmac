---
title: "Valider des messages HMAC avec Cloudflare"
date: 2022-07-05T11:03:34+02:00
draft: false
featured_image: '/img/hmac.png'
---

## Introduction

HMAC est beaucoup utilisé pour sécuriser du contenu à l'aide de token expirable. HMAC est l'acronyme de **Hash-Based Message Authentication** et le but de cet article est de voir comment l'utiliser en coordination avec votre usage de la plateforme Cloudflare.

Cloudflare propose deux outils pour gérer les tokens HMAC:
- Firewall rules https://developers.cloudflare.com/firewall/recipes/require-valid-hmac-token/
- Workers (Cloudflare's Serverless platform) - https://developers.cloudflare.com/workers/examples/signing-requests/

La première chose à savoir à propos de HMAC est de comment l'utiliser de manière optimale. HMAC est une super méthode de signature car elle est synchrone et permet à un front-end et un service de reverse proxy (comme Cloudflare) d'accepter uniquement les requêtes qui possèdent des tokens valide et non expirés. Cette méthode est totalement sans état, c'est à dire qu'aucun stockage n'est nécessaire, uniquement le protocole de signature et de vérification sont important. Une clé de signature est néanmois nécessaire et doit être partagées entre les front-end et le reverse proxy. Celle-ci est utilisé pour signer les messages HMAC mais pour aussi les vérifier.

e.g Si vous parcourez https://www.justalittlebyte.ovh/ et que vous copiez le lien rendu par **Kayak video** vous verrez que ce lien change tout le temps.

```
https://www.justalittlebyte.ovh/tokenauth/kayak.mp4?verify=1657026353-ZXJWAyFwAgJSY%2B5j3CkJE80TatA33E3MEH4D%2FkSnh7M%3D
```

Regardez comme le token est transporté dans l'URL. Dans ce cas précis, il est porté par un query string particulier **verify**. Vous verrez que le message HMAC comporte deux parties

- Le timestamp de la génération du message
- Le hashing du message complet


Parce que je suis également le priopriétaire de www.justalittlebyte.ovh, je vais vous dire comment c'est implémenté en détail


```php
<?php
// Generate valid URL parameter
$secret = "cloudflare";
$time   = time();
$param  = $time . "-" . urlencode(base64_encode(hash_hmac("sha256", "/tokenauth/kayak.mp4$time", $secret, true)));
$url    = "/tokenauth/kayak.mp4?verify=" . $param;

?>
```

C'est assez simple de générer un lien valide si vous avez la shared key (ma clé est **cloudflare**, si vous voulez jouer un peu avec)

![https://onlinephp.io/code/f/hash-hmac](/img/hmac_online.png)

Vous pourrez voir ci-dessus que j'ai triché, j'ai utilisé un timestamp EPOC dans le futur (**1757026353** c'est le 4 septembre 2025!). Je peux le faire car j'ai basiquement accès à la clé qui me permet de signer à peu près n'importe quoi, tant que le format est respecté par le système utilisé pour valider le token.
Si j'avais maintenant à forger une requête web intégrant cette signature, j'aurais aussi à encoder en base64 et urlEncode() le message, cela donne quelque chose comme ça

```
https://www.justalittlebyte.ovh/tokenauth/kayak.mp4?verify=1757026353-EjH3U8yCJVXBGs2XgTIA3J2N5XyYfHxx85wo5O5dpHw%3D
```

## Validation du token avec Cloudflare

Comprendre comment fonctionne HMAC est chose faite maintenant, voyons maintenant comment le valider efficacement sur votre site web !

### Avec Cloudflare Workers

Cloudflare workers est la plateform de serverless computing de Cloudflare. Elle permet d'executer des fonction volatiles sur le chemin de vos requêtes HTTP.

Le script validant la signature HMAC doit être le suivant

```javascript
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

### Avec une règle Firewall

Cloudflare propose un eventail large de fonctions de sécurité et l'une d'entre elles est un moteur de firewalling assez poussé. Ce moteur permet tout type de contrôle sur vos requêtes HTTP mais aussi permet l'implémentation de fonctions de transformation ou d'évaluation. HMAC en est une.

Documentation en relation avec la validation HMAC https://developers.cloudflare.com/ruleset-engine/rules-language/functions/#hmac-validation-examples

![https://onlinephp.io/code/f/hash-hmac](/img/firewall_rule.png)

```
(http.request.uri.path matches "^/tokenauth/") and not is_timed_hmac_valid_v0("cloudflare", http.request.uri, 60, http.request.timestamp.sec, 8)
```

La séquence ci-dessus reproduit l'algorithme utilisé dans ma page PHP citée plus haut, mais cette fois la logique est utilisé pour vérifier un message entrant en utilisant la clé **cloudflare**. Vous trouverez la clé partagé, l'expiration mais aussi le format du message HMAC que la règle firewall va devoir utiliser dans son évaluation. Cette fonction retourne un booleen (vrai|faux)