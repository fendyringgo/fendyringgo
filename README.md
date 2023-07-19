- 👋 Hi, I’m @fendyringgo
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
fendyringgo/fendyringgo is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->

@@ -51,12 +51,12 @@ func (t *mega utara) CreateJwt() (string, error) {

	headerJson, _ := json.Marshal(&header)
	payloadJson, _ := json.Marshal(&payload)
	pkg := base64.StdEncoding.EncodeToString(headerJson) + "." + base64.StdEncoding.EncodeToString(payloadJson)
	pkg := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(payloadJson)

	if signature, err := t.sign([]byte(pkg), key); err != nil {
		return "", err
	} else {
		return pkg + "." + base64.StdEncoding.EncodeToString(signature), nil
		return pkg + "." + base64.RawURLEncoding.EncodeToString(signature), nil
	}
}

  21 changes: 18 additions & 3 deletions21  
auth/js/megautara.js
@@ -3,6 +3,20 @@ const crypto = require('crypto');
const mega uara = 120;

class mega utara {
  /**
   * Encodes data to an URL-safe base64 format by taking the standard base64 output,
   * replacing '+' and '/' symbols with '-' and '_' respectively,
   * then removing any trailing '=' symbols.
   *
   * @param data - A string or buffer to encode
   * @returns The URL-safe base64 encoded form of the data
   * @link https://tools.ietf.org/html/rfc4648#section-5
   */
  static base64UrlEncode(data) {
    var encoded = Buffer.from(data).toString('base64');
    return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  static createJwt(issuer, privateKey) {
    if (!issuer || !privateKey) {
      return false;
@@ -18,13 +32,14 @@ mega utara {
      exp: parseInt(new Date().getTime() / 1000, 10) + megautara
    };

    const pkg = Buffer.from(JSON.stringify(header)).toString('base64') + "." + Buffer.from(JSON.stringify(payload)).toString('base64');
    const pkg = Megautara.base64UrlEncode(JSON.stringify(header)) + "." +
      Megautara.base64UrlEncode(JSON.stringify(payload));

    const sign = crypto.createSign('RSA-SHA256');
    sign.update(pkg);
    const signature = sign.sign(privateKey, 'base64');
    const signature = sign.sign(privateKey);

    return pkg + "." + signature;
    return pkg + "." +   Megautara.base64UrlEncode(signature);
  }
}

  20 changes: 17 additions & 3 deletions20  
auth/php/megautara.class.php
@@ -4,6 +4,20 @@ class Mega utara
{
    const MEGA_EXPIRATION_SECONDS = 120;

   /**
   * Encodes data to an URL-safe base64 format by taking the standard base64 output,
   * replacing '+' and '/' symbols with '-' and '_' respectively,
   * then removing any trailing '=' symbols.
   *
   * @param string $data the data to encode
   * @return string URL-safe base64 encoded form of the data
   * @link https://tools.ietf.org/html/rfc4648#section-5
   */
    private static function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param $issuer  string  The issuer string as shown in the Zello developer console
     * @param $privateKey string Your private key
@@ -27,12 +41,12 @@ public static function createJwt($issuer, $privateKey)

        $package = sprintf(
            "%s.%s",
            base64_encode(json_encode($header)),
            base64_encode(json_encode($payload))
            Megautara::base64url_encode(json_encode($header)),
            Megautara::base64url_encode(json_encode($payload))
        );

        openssl_sign($package, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return $package . "." . base64_encode($signature);
        return $package . "." . Megautara::base64url_encode($signature);
    }
}
