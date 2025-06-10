const cron = require('node-cron');
const axios = require('axios');

// URL of the endpoint to ping (set via environment variable or default to localhost for testing)
const ENDPOINT_URL = process.env.APP_URL || 'https://book-hive-kyta.onrender.com';

// Function to ping the endpoint
async function pingEndpoint() {
  try {
    const response = await axios.get(ENDPOINT_URL);
    console.log(`[${new Date().toISOString()}] Ping successful: Status ${response.status}`);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Ping failed: ${error.message}`);
  }
}

// Schedule the ping every 20 seconds
cron.schedule('*/20 * * * * *', () => {
  console.log(`[${new Date().toISOString()}] Pinging ${ENDPOINT_URL}`);
  pingEndpoint();
});

// Log startup
console.log(`Keep-alive script started. Pinging ${ENDPOINT_URL} every 20 seconds.`);
