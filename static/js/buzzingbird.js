var BuzzingBird = {};

BuzzingBird.keyStorePrefix = "_privateKey_";
BuzzingBird.requestTokenPrefix = "_requestToken_";

BuzzingBird.test = function() {
   console.log("Test successfully called.");
};

BuzzingBird.storePrivateKey = function(userid, keypair) {
   if ("object" != typeof keypair) {
      throw "An RSA keypair must be passed in.";
   } else if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaString = keypair.RSAtoJSON();

   $.totalStorage(key, rsaString);
};

BuzzingBird.getPrivateKey = function(userid) {
   if ("string" != typeof userid) {
      throw "A valid userid must be passed in.";
   }

   var key = this.keyStorePrefix + userid;

   var rsaString = $.totalStorage(key);

   return RSAParse(rsaString);
};

BuzzingBird.createRequestToken = function(hashtag, keypair, thisuser, target_user) {
   if ("string" != typeof hashtag) {
      throw "A valid hashtag string must be passed in.";
   } else if ("object" != typeof keypair ) {
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

   var sigma = approvedToken.multiply(r.modInverse(generatedRSAKey.n)).mod(generatedRSAKey.n);

   rtData.sigma = sigma;
   $.totalStorage(localStoreKey, rtData);

   return sigma;
};

BuzzingBird.approveRequestToken = function(keypair, requestToken) {
   if ("object" != typeof keypair) {
      throw "A valid RSAKey must be passed in.";
   }
   return keypair.doPrivate(requestToken);
};

