#!/usr/bin/env node

/**
 * Production Deployment Script for Event Joining App
 * 
 * This script handles:
 * - Environment validation
 * - Dependency installation
 * - Database setup verification
 * - Security configuration
 * - Service startup
 * - Health checks
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const { productionConfig, validateEnvironment, securityChecklist } = require('./production.config.js');

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

class DeploymentManager {
  constructor() {
    this.projectRoot = path.resolve(__dirname, '..');
    this.logFile = path.join(this.projectRoot, 'logs', 'deployment.log');
    this.startTime = new Date();
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    // Console output with colors
    const colorMap = {
      info: colors.blue,
      success: colors.green,
      warning: colors.yellow,
      error: colors.red
    };
    
    console.log(`${colorMap[level] || colors.reset}${logMessage}${colors.reset}`);
    
    // File logging
    this.ensureLogDirectory();
    fs.appendFileSync(this.logFile, logMessage + '\n');
  }

  ensureLogDirectory() {
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  async executeStep(stepName, stepFunction) {
    this.log(`Starting: ${stepName}`);
    try {
      await stepFunction();
      this.log(`✓ Completed: ${stepName}`, 'success');
      return true;
    } catch (error) {
      this.log(`✗ Failed: ${stepName} - ${error.message}`, 'error');
      throw error;
    }
  }

  checkNodeVersion() {
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    
    if (majorVersion < 16) {
      throw new Error(`Node.js version ${nodeVersion} is not supported. Please use Node.js 16 or higher.`);
    }
    
    this.log(`Node.js version: ${nodeVersion}`);
  }

  validateEnvironmentFile() {
    const envFile = path.join(this.projectRoot, '.env.production');
    
    if (!fs.existsSync(envFile)) {
      throw new Error(
        'Production environment file not found. Please copy .env.production.template to .env.production and configure it.'
      );
    }
    
    // Load production environment
    require('dotenv').config({ path: envFile });
    
    // Validate required environment variables
    validateEnvironment();
    
    this.log('Environment validation passed');
  }

  installDependencies() {
    this.log('Installing production dependencies...');
    
    try {
      execSync('npm ci --only=production', {
        cwd: this.projectRoot,
        stdio: 'inherit'
      });
    } catch (error) {
      throw new Error(`Failed to install dependencies: ${error.message}`);
    }
  }

  runSecurityAudit() {
    this.log('Running security audit...');
    
    try {
      execSync('npm audit --audit-level=high', {
        cwd: this.projectRoot,
        stdio: 'inherit'
      });
    } catch (error) {
      this.log('Security audit found issues. Please review and fix before deploying.', 'warning');
      // Don't fail deployment for audit issues, but log them
    }
  }

  async testDatabaseConnection() {
    this.log('Testing database connection...');
    
    try {
      // Import Supabase client
      const { createClient } = require('@supabase/supabase-js');
      
      const supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
      );
      
      // Test connection with a simple query
      const { data, error } = await supabase
        .from('users')
        .select('count')
        .limit(1);
      
      if (error) {
        throw new Error(`Database connection failed: ${error.message}`);
      }
      
      this.log('Database connection successful');
    } catch (error) {
      throw new Error(`Database test failed: ${error.message}`);
    }
  }

  runTests() {
    this.log('Running test suite...');
    
    try {
      execSync('npm run test:unit', {
        cwd: this.projectRoot,
        stdio: 'inherit',
        env: { ...process.env, NODE_ENV: 'test' }
      });
    } catch (error) {
      throw new Error(`Tests failed: ${error.message}`);
    }
  }

  createSystemdService() {
    if (process.platform !== 'linux') {
      this.log('Skipping systemd service creation (not on Linux)', 'warning');
      return;
    }
    
    const serviceName = 'event-joining-app';
    const serviceFile = `/etc/systemd/system/${serviceName}.service`;
    
    const serviceContent = `[Unit]
Description=Event Joining App
After=network.target

[Service]
Type=simple
User=nodejs
WorkingDirectory=${this.projectRoot}
EnvironmentFile=${path.join(this.projectRoot, '.env.production')}
ExecStart=/usr/bin/node ${path.join(this.projectRoot, 'server.js')}
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${serviceName}

[Install]
WantedBy=multi-user.target
`;
    
    try {
      fs.writeFileSync(serviceFile, serviceContent);
      execSync('systemctl daemon-reload');
      execSync(`systemctl enable ${serviceName}`);
      this.log('Systemd service created and enabled');
    } catch (error) {
      this.log(`Failed to create systemd service: ${error.message}`, 'warning');
    }
  }

  setupLogRotation() {
    if (process.platform !== 'linux') {
      this.log('Skipping log rotation setup (not on Linux)', 'warning');
      return;
    }
    
    const logrotateConfig = `/etc/logrotate.d/event-joining-app`;
    const logrotateContent = `${path.join(this.projectRoot, 'logs')}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 nodejs nodejs
    postrotate
        systemctl reload event-joining-app || true
    endscript
}
`;
    
    try {
      fs.writeFileSync(logrotateConfig, logrotateContent);
      this.log('Log rotation configured');
    } catch (error) {
      this.log(`Failed to setup log rotation: ${error.message}`, 'warning');
    }
  }

  async performHealthCheck() {
    this.log('Performing health check...');
    
    // Start the server in background for health check
    const serverProcess = spawn('node', ['server.js'], {
      cwd: this.projectRoot,
      env: { ...process.env, NODE_ENV: 'production' },
      detached: false
    });
    
    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    try {
      const http = require('http');
      const port = process.env.PORT || 3000;
      
      const healthCheckPromise = new Promise((resolve, reject) => {
        const req = http.get(`http://localhost:${port}/health`, (res) => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            reject(new Error(`Health check failed with status: ${res.statusCode}`));
          }
        });
        
        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Health check timeout')));
      });
      
      await healthCheckPromise;
      this.log('Health check passed');
    } catch (error) {
      throw new Error(`Health check failed: ${error.message}`);
    } finally {
      // Stop the test server
      serverProcess.kill();
    }
  }

  printSecurityChecklist() {
    this.log('\n=== SECURITY CHECKLIST ===', 'info');
    
    Object.entries(securityChecklist).forEach(([category, items]) => {
      this.log(`\n${category.toUpperCase()}:`, 'info');
      items.forEach(item => {
        this.log(`  [ ] ${item}`, 'info');
      });
    });
    
    this.log('\nPlease review and complete the security checklist before going live.', 'warning');
  }

  printDeploymentSummary() {
    const duration = Math.round((new Date() - this.startTime) / 1000);
    
    this.log('\n=== DEPLOYMENT SUMMARY ===', 'success');
    this.log(`Deployment completed in ${duration} seconds`, 'success');
    this.log(`Project root: ${this.projectRoot}`, 'info');
    this.log(`Log file: ${this.logFile}`, 'info');
    this.log(`Server port: ${process.env.PORT || 3000}`, 'info');
    this.log(`Environment: ${process.env.NODE_ENV}`, 'info');
    
    this.log('\nNext steps:', 'info');
    this.log('1. Review the security checklist above', 'info');
    this.log('2. Configure your reverse proxy (nginx/Apache)', 'info');
    this.log('3. Set up SSL certificates', 'info');
    this.log('4. Configure firewall rules', 'info');
    this.log('5. Set up monitoring and alerting', 'info');
    this.log('6. Start the service: systemctl start event-joining-app', 'info');
  }

  async deploy() {
    try {
      this.log('Starting production deployment...', 'info');
      
      await this.executeStep('Node.js version check', () => this.checkNodeVersion());
      await this.executeStep('Environment validation', () => this.validateEnvironmentFile());
      await this.executeStep('Dependency installation', () => this.installDependencies());
      await this.executeStep('Security audit', () => this.runSecurityAudit());
      await this.executeStep('Database connection test', () => this.testDatabaseConnection());
      await this.executeStep('Test suite execution', () => this.runTests());
      await this.executeStep('Systemd service creation', () => this.createSystemdService());
      await this.executeStep('Log rotation setup', () => this.setupLogRotation());
      await this.executeStep('Health check', () => this.performHealthCheck());
      
      this.printSecurityChecklist();
      this.printDeploymentSummary();
      
    } catch (error) {
      this.log(`Deployment failed: ${error.message}`, 'error');
      process.exit(1);
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0];
  
  const deployment = new DeploymentManager();
  
  switch (command) {
    case 'deploy':
      deployment.deploy();
      break;
      
    case 'health-check':
      deployment.performHealthCheck()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
      break;
      
    case 'validate-env':
      try {
        deployment.validateEnvironmentFile();
        console.log('Environment validation passed');
        process.exit(0);
      } catch (error) {
        console.error('Environment validation failed:', error.message);
        process.exit(1);
      }
      break;
      
    default:
      console.log('Usage: node deploy.js [deploy|health-check|validate-env]');
      console.log('');
      console.log('Commands:');
      console.log('  deploy       - Full production deployment');
      console.log('  health-check - Test application health');
      console.log('  validate-env - Validate environment configuration');
      process.exit(1);
  }
}

module.exports = DeploymentManager;