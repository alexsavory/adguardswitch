const axios = require('axios');

let Service, Characteristic;

module.exports = (homebridge) => {
  Service = homebridge.hap.Service;
  Characteristic = homebridge.hap.Characteristic;

  homebridge.registerAccessory(
    'homebridge-adguard-dns-switch',
    'AdGuardDNSSwitch',
    AdGuardDNSSwitch
  );
};

class AdGuardDNSSwitch {
  constructor(log, config) {
    this.log = log;
    this.name = config.name || 'AdGuard DNS Protection';
    this.dnsServerId = config.dnsServerId;
    this.username = config.username;
    this.password = config.password;
    this.mfa_token = config.mfa_token || null;
    this.debugEnabled = config.debug === true; // debug flag from config
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    this.apiBaseUrl = 'https://api.adguard-dns.io/oapi/v1';

    if (!this.dnsServerId || !this.username || !this.password) {
      throw new Error('dnsServerId, username, and password are required in config');
    }

    this.service = new Service.Switch(this.name);
    this.service.getCharacteristic(Characteristic.On)
      .on('get', this.handleGet.bind(this))
      .on('set', this.handleSet.bind(this));

    this.authenticate().then(() => {
      this.logInfo('Authenticated with AdGuard DNS API.');
    }).catch((error) => {
      this.logError('Authentication error:', error.message);
    });
  }

  logDebug(...args) {
    if (this.debugEnabled) {
      this.log.debug(...args);
    }
  }

  logInfo(...args) {
    this.log.info(...args);
  }

  logError(...args) {
    this.log.error(...args);
  }

  async apiRequest(method, url, headers = {}, data = null) {
    try {
      this.logDebug(`[API] ${method.toUpperCase()} ${url}`);
      if (data) {
        this.logDebug(`[API] Payload: ${JSON.stringify(data)}`);
      }
      const response = await axios({
        method,
        url,
        headers,
        data
      });
      this.logDebug(`[API] Response status: ${response.status}`);
      if (response.data) {
        this.logDebug(`[API] Response body: ${JSON.stringify(response.data)}`);
      }
      return response;
    } catch (error) {
      if (error.response) {
        this.logError(`[API] Error ${error.response.status}: ${JSON.stringify(error.response.data)}`);
      } else {
        this.logError('[API] Network or code error:', error.message);
      }
      throw error;
    }
  }

  async authenticate() {
    try {
      this.logDebug('Authenticating with AdGuard DNS API...');
      const data = new URLSearchParams();
      data.append('username', this.username);
      data.append('password', this.password);
      if (this.mfa_token) {
        data.append('mfa_token', this.mfa_token);
      }
      const response = await this.apiRequest(
        'post',
        `${this.apiBaseUrl}/oauth_token`,
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        data
      );
      this.accessToken = response.data.access_token;
      this.refreshToken = response.data.refresh_token;
      this.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
      this.logInfo('Got new access token and refresh token.');
    } catch (error) {
      this.logError('Failed to authenticate using credentials:', error.message);
      throw error;
    }
  }

  async refreshAccessToken() {
    try {
      this.logDebug('Refreshing AdGuard DNS access token...');
      const data = new URLSearchParams();
      data.append('refresh_token', this.refreshToken);
      const response = await this.apiRequest(
        'post',
        `${this.apiBaseUrl}/oauth_token`,
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        data
      );
      this.accessToken = response.data.access_token;
      this.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
      this.logInfo('Access token refreshed.');
    } catch (error) {
      this.logError('Failed to refresh access token:', error.message);
      throw error;
    }
  }

  async ensureValidToken() {
    if (!this.accessToken || Date.now() + 60000 > this.tokenExpiry) {
      this.logDebug('Access token is missing or about to expire, fetching new token...');
      if (this.refreshToken) {
        await this.refreshAccessToken();
      } else {
        await this.authenticate();
      }
    }
  }

  async handleGet(callback) {
    try {
      this.logDebug('Getting current protection_enabled state...');
      await this.ensureValidToken();
      const response = await this.apiRequest(
        'get',
        `${this.apiBaseUrl}/dns_servers/${this.dnsServerId}`,
        { Authorization: `Bearer ${this.accessToken}` }
      );
      const enabled = response.data.settings.protection_enabled;
      this.logDebug(`Current protection_enabled value is ${enabled}`);
      callback(null, enabled);
    } catch (error) {
      this.logError('Error getting protection_enabled:', error.message);
      callback(error);
    }
  }

  async handleSet(value, callback) {
    try {
      await this.ensureValidToken();
      this.logDebug(`Toggling protection_enabled: attempting to set to ${value}`);
      const payload = { protection_enabled: value };
      await this.apiRequest(
        'put',
        `${this.apiBaseUrl}/dns_servers/${this.dnsServerId}/settings`,
        { Authorization: `Bearer ${this.accessToken}` },
        payload
      );
      if (value === true) {
        this.logInfo('protection_enabled was ENABLED (switch ON)');
        this.logDebug('Successfully enabled AdGuard DNS protection.');
      } else {
        this.logInfo('protection_enabled was DISABLED (switch OFF)');
        this.logDebug('Successfully disabled AdGuard DNS protection.');
      }
      callback(null);
    } catch (error) {
      this.logError('Error setting protection_enabled:', error.message);
      callback(error);
    }
  }

  getServices() {
    return [this.service];
  }
}
