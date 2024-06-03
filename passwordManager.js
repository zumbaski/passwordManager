const bcrypt = require('bcrypt');
const crypto = require('crypto');

const saltRounds = 10;

// This Function to generate a secure password
function generatePassword(length = 12) {
  return crypto.randomBytes(length).toString('hex');
}

// Function to hash a password
async function hashPassword(password) {
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    console.error('Error hashing password:', error);
    throw error;
  }
}

// Function to compare a password with a hashed password
async function comparePassword(password, hash) {
  try {
    const match = await bcrypt.compare(password, hash);
    return match;
  } catch (error) {
    console.error('Error comparing password:', error);
    throw error;
  }
}

// Example usage
(async () => {
  const plainPassword = generatePassword();
  console.log('Generated Password:', plainPassword);

  const hashedPassword = await hashPassword(plainPassword);
  console.log('Hashed Password:', hashedPassword);

  const isMatch = await comparePassword(plainPassword, hashedPassword);
  console.log('Password match:', isMatch);
})();
