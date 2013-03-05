var BuzzingBird = {};

BuzzingBird.keyStorePrefix = "_privateKey_";
BuzzingBird.requestTokenPrefix = "_requestToken_";

BuzzingBird.storePrivateKey = function(userid, keypair) {
   if ("object" != typeof keypair) {
      throw "An RSA keypair must be passed in.";
   } else if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaString = keypair.toJSON();

   $.totalStorage(key, rsaString);

   console.log('Successfully stored private key.');
};

BuzzingBird.getPrivateKey = function(userid) {
   if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaObject = $.totalStorage(key);

   var rsa = new RSAKey();

   rsa.setPrivateEx(rsaObject.n, rsaObject.e, rsaObject.d, rsaObject.p, rsaObject.q, rsaObject.dmp1, rsaObject.dmq1, rsaObject.coeff);

   console.log("Retrieved private key");

   return rsa;
};

BuzzingBird.createRequestToken = function(hashtag, keypair, bits, thisuser, target_user) {
   if ("string" != typeof hashtag) {
      throw "A valid hashtag string must be passed in.";
   } else if ("object" != typeof keypair ) {
      throw "A valid RSAKey must be passed in.";
   } else if ("number" != typeof bits) {
      throw "A valid number of bits must be passed in.";
   } else if ("string" != typeof thisuser) {
      throw "A valid user id must be passed in for thisuser.";
   } else if ("string" != typeof target_user) {
      throw "A valid user must be passed in.";
   }

   var randGen = new SecureRandom();
   var r = new BigInteger(bits, randGen);

   var encryptedR = keypair.doPublic(r);
   var hashedTag = sha256.hex(hashtag);
   var hashedTagBigInt = pkcs1pad2_deterministic(hashedTag, (keypair.n.bitLength() + 7) >> 3);

   var result = hashedTagBigInt.multiply(encryptedR).mod(keypair.n);

   var localStoreKey = this.requestTokenPrefix + thisuser + "_" + target_user;

   $.totalStorage(localStoreKey, {'ht' : hashtag, 'r' : r.toString(16) });

   return result;
};

BuzzingBird.acceptRequestToken = function(keypair, thisuser, target_user, approvedToken) {
   if ("object" != typeof keypair ) {
      throw "A valid RSAKey must be passed in.";
   } else if ("string" != typeof thisuser) {
      throw "A valid user id must be passed in for thisuser.";
   } else if ("string" != typeof target_user) {
      throw "A valid user must be passed in.";
   }

   var localStoreKey = this.requestTokenPrefix + thisuser + "_" + target_user;

   var rtData = $.totalStorage(localStoreKey);
   var r = new BigInteger(rtData.r, 16);

   var sigma = approvedToken.multiply(r.modInverse(keypair.n)).mod(keypair.n);

   rtData.sigma = sigma.toString(16);
   $.totalStorage(localStoreKey, rtData);

   return MD5(sigma.toString(16));
};

BuzzingBird.approveRequestToken = function(keypair, requestToken) {
   if ("object" != typeof keypair) {
      throw "A valid RSAKey must be passed in.";
   }
   return keypair.doPrivate(requestToken);
};

