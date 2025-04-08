const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = "myJwtSecretKey"; // used for signing the JWT
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes = 256 bits
const IV = crypto.randomBytes(16); // 16 bytes = 128 bits

// Encrypt the JWT
const encrypt = (payload) => {
  // Step 1: Create a JWT token
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

  // Step 2: Encrypt the token
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  // Return encrypted token along with IV (needed for decryption)
  return {
    token: encrypted,
    iv: IV.toString("hex") // send this along with encrypted token
  };
};

// Decrypt the encrypted token
const decrypt = (encryptedToken, ivHex) => {
  const iv = Buffer.from(ivHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedToken, "hex", "utf8");
  decrypted += decipher.final("utf8");

  // Verify and decode JWT
  const decoded = jwt.verify(decrypted, JWT_SECRET);
  return decoded;
};

module.exports = {
  encrypt,
  decrypt
};
