var BuzzingBird = {};

BuzzingBird.keyStorePrefix = "_privateKey_";
BuzzingBird.requestTokenPrefix = "_requestToken_";

BuzzingBird.test = function() {
   console.log("Test successfully called.");
};

BuzzingBird.storePrivateKey = function(userid, keypair) {
   if ("RSAKey" != typeof keypair) {
      throw "An RSA keypair must be passed in.";
   } else if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaString = keypair.RSAtoJSON();

   $.localStorage(key, rsaString);
};

BuzzingBird.getPrivateKey = function(userid) {
   if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaString = $.localStorage(key);

   return RSAParse(rsaString);
};

BuzzingBird.createRequestToken = function(hashtag, keypair, thisuser, target_user) {
   if ("string" != typeof hashtag) {
      throw "A valid hashtag string must be passed in.";
   } else if ("RSAKey" != typeof keypair ) {
      throw "A valid RSAKey must be passed in.";
   } else if ("string" != typeof thisuser) {
      throw "A valid user id must be passed in for thisuser.";
   } else if ("string" != typeof target_user) {
      throw "A valid user must be passed in.";
   }

   var randGen = new SecureRandom();
   var r = new BigInteger(Bits, randGen);

   var encryptedR = keypair.doPublic(r);
   var hashedTag = sha256.hex(hashtag);
   var hashedTagBigInt = pkcs1pad2(hashedTag, (keypair.n.bitLength() + 7) >> 3);

   var result = hashedTagBigInt.multiply(encryptedR).mod(keypair.n);
   // console.log("H(x) * r ^ e = " + result.toString(16));

   var localStoreKey = this.requestTokenPrefix + thisuser + "_" + target_user;

   $.localStorage(localStoreKey, {'ht' : hashtag, 'r' : r.toString(16)});

   return result;
};

BuzzingBird.acceptRequestToken = function(keypair, thisuser, target_user, approvedToken) {
   if ("RSAKey" != typeof keypair ) {
      throw "A valid RSAKey must be passed in.";
   } else if ("string" != typeof thisuser) {
      throw "A valid user id must be passed in for thisuser.";
   } else if ("string" != typeof target_user) {
      throw "A valid user must be passed in.";
   }

   var localStoreKey = this.requestTokenPrefix + thisuser + "_" + target_user;

   var rtData = $.localStorage(localStoreKey);
   var r = JSON.parse(rtData.r);

   var sigma = approvedToken.multiply(r.modInverse(generatedRSAKey.n)).mod(generatedRSAKey.n);

   rtData.sigma = sigma;
   $.localStorage(localStoreKey, rtData);
};

BuzzingBird.approveRequestToken = function(keypair) {
   if ("RSAKey" != typeof keypair) {
      throw "A valid RSAKey must be passed in.";
   }

   return keypair.doPrivate(result);
};

