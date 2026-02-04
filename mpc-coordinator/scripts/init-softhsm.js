#!/usr/bin/env node

/**
 * SoftHSM Initialization Script
 *
 * This script will:
 * 1. Check if SoftHSM is installed
 * 2. Create configuration files
 * 3. Initialize token
 * 4. Set PIN codes
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG_DIR = path.join(os.homedir(), '.softhsm');
const CONFIG_FILE = path.join(CONFIG_DIR, 'softhsm2.conf');
const TOKENS_DIR = path.join(CONFIG_DIR, 'tokens');
const TOKEN_LABEL = process.env.HSM_TOKEN_LABEL || 'MPC-Token';
const USER_PIN = process.env.HSM_USER_PIN || '1234';
const SO_PIN = process.env.HSM_SO_PIN || '5678';

console.log('=== SoftHSM Initialization ===\n');

// Step 1: Check if SoftHSM is installed
console.log('Step 1: Checking SoftHSM...');
try {
  const version = execSync('softhsm2-util --version', { encoding: 'utf-8' });
  console.log('✅ SoftHSM installed:', version.trim().split('\n')[0]);
} catch (error) {
  console.error('❌ SoftHSM not installed');
  console.error('Please install SoftHSM:');
  console.error('  Ubuntu/Debian: sudo apt install softhsm2');
  console.error('  macOS: brew install softhsm');
  process.exit(1);
}

// Step 2: Create configuration directories
console.log('\nStep 2: Creating configuration directories...');
if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  console.log('✅ Directory created:', CONFIG_DIR);
} else {
  console.log('✅ Directory already exists:', CONFIG_DIR);
}

if (!fs.existsSync(TOKENS_DIR)) {
  fs.mkdirSync(TOKENS_DIR, { recursive: true });
  console.log('✅ Directory created:', TOKENS_DIR);
} else {
  console.log('✅ Directory already exists:', TOKENS_DIR);
}

// Step 3: Create configuration file
console.log('\nStep 3: Creating configuration file...');
const configContent = `# SoftHSM v2 configuration file

directories.tokendir = ${TOKENS_DIR}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = INFO

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
`;

fs.writeFileSync(CONFIG_FILE, configContent);
console.log('✅ Configuration file created:', CONFIG_FILE);

// Set environment variable
process.env.SOFTHSM2_CONF = CONFIG_FILE;

// Step 4: Initialize token
console.log('\nStep 4: Initializing token...');
try {
  // Check if token already exists
  const tokens = execSync('softhsm2-util --show-slots', {
    encoding: 'utf-8',
    env: { ...process.env, SOFTHSM2_CONF: CONFIG_FILE }
  });

  if (tokens.includes(TOKEN_LABEL)) {
    console.log(`⚠️  Token "${TOKEN_LABEL}" already exists`);
    console.log('To reinitialize, first delete the token:');
    console.log(`  softhsm2-util --delete-token --token "${TOKEN_LABEL}"`);
  } else {
    // Initialize new token
    const initCmd = `softhsm2-util --init-token --slot 0 --label "${TOKEN_LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}"`;
    execSync(initCmd, {
      stdio: 'inherit',
      env: { ...process.env, SOFTHSM2_CONF: CONFIG_FILE }
    });
    console.log(`✅ Token "${TOKEN_LABEL}" initialized successfully`);
  }
} catch (error) {
  console.error('❌ Failed to initialize token:', error.message);
  process.exit(1);
}

// Step 5: Display token information
console.log('\nStep 5: Token information:');
try {
  const slotsInfo = execSync('softhsm2-util --show-slots', {
    encoding: 'utf-8',
    env: { ...process.env, SOFTHSM2_CONF: CONFIG_FILE }
  });
  console.log(slotsInfo);
} catch (error) {
  console.error('❌ Unable to retrieve token information:', error.message);
}

// Step 6: Update .env file
console.log('Step 6: Updating environment variables...');
const envFile = path.join(__dirname, '..', '.env');
const envExampleFile = path.join(__dirname, '..', '.env.example');

if (!fs.existsSync(envFile) && fs.existsSync(envExampleFile)) {
  fs.copyFileSync(envExampleFile, envFile);
  console.log('✅ .env file created');
}

if (fs.existsSync(envFile)) {
  let envContent = fs.readFileSync(envFile, 'utf-8');

  // Update SOFTHSM2_CONF path
  if (envContent.includes('SOFTHSM2_CONF=')) {
    envContent = envContent.replace(
      /SOFTHSM2_CONF=.*/,
      `SOFTHSM2_CONF=${CONFIG_FILE}`
    );
  } else {
    envContent += `\nSOFTHSM2_CONF=${CONFIG_FILE}\n`;
  }

  fs.writeFileSync(envFile, envContent);
  console.log('✅ .env file updated');
}

console.log('\n=== Initialization Complete ===\n');
console.log('Configuration:');
console.log(`  Config file: ${CONFIG_FILE}`);
console.log(`  Token directory: ${TOKENS_DIR}`);
console.log(`  Token label: ${TOKEN_LABEL}`);
console.log(`  User PIN: ${USER_PIN}`);
console.log(`  SO PIN: ${SO_PIN}`);
console.log('');
console.log('Next steps:');
console.log('  1. Verify SOFTHSM2_CONF path in .env file');
console.log('  2. Run npm install to install dependencies');
console.log('  3. Run npx prisma migrate dev to initialize database');
console.log('  4. Run npm run dev to start the service');
