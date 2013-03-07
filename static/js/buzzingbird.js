var BuzzingBird = {};

BuzzingBird.keyStorePrefix = "_privateKey_";
BuzzingBird.requestTokenPrefix = "_requestToken_";

BuzzingBird.hash2bytes = function(hash) {
   //Assuming a SHA-1 hash, we should produce an array with
   //20 bytes, as each letter pair corresponds to a full byte.
   var bytes = [];
   for (var i = 0, n = hash.length; i < n; i += 2) {
      var pair = hash.substr(i, 2);
      bytes.push(parseInt(pair, 16));
   }

   return bytes;
};

BuzzingBird.generateAESKeyFromHash = function(hash) {
   unpaddedBytes = BuzzingBird.hash2bytes(hash);
   paddedBytes = cryptico.pad16(unpaddedBytes);

   return paddedBytes;
};

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

   var sigmas = rtData.sigmas;
   if (sigmas == null) {
      sigmas = [];
   }

   sigmas.push(sigma.toString(16));
   rtData.sigmas = sigmas;

   $.totalStorage(localStoreKey, rtData);

   return MD5(sigma.toString(16));
};

BuzzingBird.approveRequestToken = function(keypair, requestToken) {
   if ("object" != typeof keypair) {
      throw "A valid RSAKey must be passed in.";
   }
   return keypair.doPrivate(requestToken);
};


BuzzingBird.computeSigma = function(keypair, hashtag) {
   if ("object" != typeof keypair) {
      throw "A valid RSAKey must be provided.";
   } else if ("string" != typeof hashtag) {
      throw "A valid hashtag must be passed in.";
   }

   //Compute sigma for hashtag.
   var hashedTag           = sha256.hex(hashtag);
   var hashedTagBigInt     = pkcs1pad2_deterministic(hashedTag, (keypair.n.bitLength() + 7) >> 3);

   var sigma               = keypair.doPrivate(hashedTagBigInt);
   return sigma;
};

BuzzingBird.generateToken = function(keypair, hashtag) {
   var sigma = BuzzingBird.computeSigma(keypair, hashtag);
   var token = MD5(sigma.toString(16));

   return token;
};

BuzzingBird.encryptMessage = function(keypair, hashtag, plainMessage) {
   //Encrypt a message using a key generated from a message's hashtag.
   if ("object" != typeof keypair) {
      throw "A valid RSAKey must be provided.";
   } else if ("string" != typeof hashtag) {
      throw "A valid hashtag must be passed in.";
   } else if ("string" != typeof plainMessage) {
      throw "A valid plainMessage must be passed in.";
   }

   var sigma               = BuzzingBird.computeSigma(keypair, hashtag);
   var messageKey          = sha1.hex(sigma.toString(16));

   var aesKey              = BuzzingBird.generateAESKeyFromHash(messageKey);
   var encryptedMessage    = cryptico.encryptAESCBC(plainMessage, aesKey);

   return encryptedMessage;
};

BuzzingBird.decryptMessage = function(sigmaString, encryptedMessage) {
   //Decrypt a message using a key generated from a pre-stored sigma string.
   if ("string" != typeof sigmaString) {
      throw "A valid hashtag must be passed in.";
   } else if ("string" != typeof encryptedMessage) {
      throw "A valid message must be passed in.";
   }

   var messageKey          = sha1.hex(sigmaString);

   var aesKey              = BuzzingBird.generateAESKeyFromHash(messageKey);
   var decryptedMessage    = cryptico.decryptAESCBC(encryptedMessage, aesKey);

   return decryptedMessage;
};

BuzzingBird.getHashTagsFromTweet = function(tweet) {
   return tweet.match(/#\w*\d*/g);
};

BuzzingBird.getFirstHashtagFromTweet = function(tweet) {
   var tweets = BuzzingBird.getHashTagsFromTweet(tweet);
   return tweets === null ? null : tweets[0];
};

BuzzingBird.recoverSigmaForToken = function(thisuser, target_user, token) {
   //Obtain the sigma from local storage that will produce the given token.
   //This will then be used to decrypt each tweet in .decryptMessage().
   var localStoreKey = this.requestTokenPrefix + thisuser + "_" + target_user;
   var subscriptionData = $.totalStorage(localStoreKey);
   var sigmas = subscriptionData.sigmas;

   //TODO: add support for multiple hashtags/sigmas.
   for(var i = 0, n = sigmas.length; i < n; i++) {
      if (MD5(sigmas[i]) === token) {
         return sigmas[i];
      }
   }

   return null;
};

