const { fork } = require('child_process');

// Fork the main application
const appProcess = fork('app.js');

// Fork the keep-alive script
const keepAliveProcess = fork('scripts/keep-alive.js');

// Log process startup
console.log('Started app.js and keep-alive.js');

// Handle process errors or exits
appProcess.on('error', (err) => {
  console.error('app.js error:', err);
});

appProcess.on('exit', (code) => {
  console.log(`app.js exited with code ${code}`);
});

keepAliveProcess.on('error', (err) => {
  console.error('keep-alive.js error:', err);
});

keepAliveProcess.on('exit', (code) => {
  console.log(`keep-alive.js exited with code ${code}`);
});