const WhiteSpace = function (iv, key) {
  let byteArrayOutputStream = java.io.ByteArrayOutputStream();
  iv.forEach(e => byteArrayOutputStream.write(java.lang.Byte(e)));
  this.iv = javax.crypto.spec.IvParameterSpec(byteArrayOutputStream.toByteArray()); //IV (Initial Vector) 설정
  this.secretKey = javax.crypto.spec.SecretKeySpec(java.lang.String(key).getBytes(), 'AES');
  this.cipher = javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding')
};

WhiteSpace.prototype.encrypt = function (toEncrypt) {
  this.cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, this.secretKey, this.iv);
  return this.cipher.doFinal(java.lang.String(toEncrypt).getBytes()) //문자열을 암호화
    .map(e => (e < 0 ? e + 256 : e).toString(2).padStart(8, "0")).join("") //암호화 결과를 이진수 문자열로 변환
    .replace(/0/g, "\u200b").replace(/1/g, "\u200d"); //0과 1을 문자인 U+200B, U+200D로 각각 치환 (둘 다 투명 문자)
};

WhiteSpace.prototype.decrypt = function (toDecrypt) {
  let byteArrayOutputStream = java.io.ByteArrayOutputStream();
  toDecrypt
    .replace(/\u200b/g, "0").replace(/\u200d/g, "1") //U+200B, U+200D를 0과 1로 각각 치환
    .match(/[01]{1,8}/g).map(e => { //이진수를 1바이트에 해당하는 길이마다 잘라서
      let n = parseInt(e, 2); //이진수로 읽은 뒤
      byteArrayOutputStream.write(java.lang.Byte(n >= 128 ? n - 256 : n)); //바이트 배열로 변환
    });
  this.cipher.init(javax.crypto.Cipher.DECRYPT_MODE, this.secretKey, this.iv);
  return java.lang.String(this.cipher.doFinal(byteArrayOutputStream.toByteArray())); //복호화
};

/*************************************************************************************************
주의 사항: 
 - 1. IV는 -128 ~ 127의 정수값(자바의 byte 자료형의 범위)이 16개 있는 배열이어야 합니다.
 - 2. 암호화 키는 16 바이트(AES-128)거나 24 바이트(AES-192), 혹은 32 바이트(AES-256)여야 합니다.

사용법 예시: 
let ws = new WhiteSpace(
  [127, 18, 18, -89, 57, -39, 32, 3, 0, -18, -74, 62, 92, -102, -60, 63], 
  "0123456789abcdefghijklmnopqrstuv"
);
ws.encrypt("가나다");
*************************************************************************************************/