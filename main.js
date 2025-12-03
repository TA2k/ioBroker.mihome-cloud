"use strict";

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("json2iob");
const RC4Crypt = require("./lib/rc4");
const configDes = require("./lib/configDes");
const crypto = require("crypto");
const tough = require("tough-cookie");
const AdmZip = require("adm-zip");
const { HttpsCookieAgent } = require("http-cookie-agent/http");

class MihomeCloud extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: "mihome-cloud",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));

    // Constants
    this.MAX_JSON_PARAMS_LENGTH = 112; // Max chars for get_prop params array
    this.QR_CODE_TIMEOUT = 300; // QR code valid for 5 minutes (seconds)
    this.LONG_POLL_TIMEOUT = 10000; // Long polling timeout per request (ms)
    this.EVENT_AUTO_RESET_DELAY = 5000; // Auto-reset events after 5 seconds

    // Device tracking
    this.deviceArray = [];
    this.deviceDicts = {};
    this.local = "de";
    this.deviceId = this.randomString(40);
    this.remoteCommands = {};
    this.specStatusDict = {};
    this.specPropsToIdDict = {};
    this.specActionsToIdDict = {};
    this.specEventsToIdDict = {};
    this.customPropsDict = {}; // Track custom properties for polling
    this.vacuumStatusDevices = []; // Track devices that support get_status (vacuums, etc.)
    this.usedStateNames = {}; // Track first occurrence of state names per device
    this.scenes = {};
    this.unsupportedPluginStatus = {}; // Track devices that don't support plugin status
    this.json2iob = new Json2iob(this);

    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      maxRedirects: 5, // Allow some redirects by default
      httpsAgent: new HttpsCookieAgent({
        cookies: {
          jar: this.cookieJar,
        },
      }),
    });

    // Cookie and session persistence via ioBroker state
    this.cookieStateId = "auth.session";
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState("info.connection", false, true);
    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }
    this.header = {
      "miot-encrypt-algorithm": "ENCRYPT-RC4",
      "content-type": "application/x-www-form-urlencoded",
      accept: "*/*",
      "accept-language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
      "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
      "operate-common":
        "_region=" +
        this.config.region +
        "&_language=" +
        this.local +
        "_deviceId=" +
        this.deviceId +
        "&_appVersion=10.5.201&_platform=1&_platformVersion=14.8",
      "user-agent": "APP/com.xiaomi.mihome APPV/10.5.201",
    };
    this.config.region = this.config.region === "cn" ? "" : this.config.region + ".";
    this.updateInterval = null;
    this.refreshTokenTimeout = null;
    this.session = {};

    this.subscribeStates("*");

    // Try to load saved cookies first
    this.log.info("Attempting to load saved cookies...");
    const cookiesLoaded = await this.loadCookies();

    if (cookiesLoaded) {
      this.log.info("Cookies loaded, attempting to resume session...");

      // Validate ssecurity - must be done BEFORE trying to use the session
      // Valid ssecurity is typically 24-32 characters (Base64 encoded)
      // Check for corruption: too short (<20) or contains invalid characters
      if (this.session && this.session.ssecurity) {
        this.log.debug("Found ssecurity with length: " + this.session.ssecurity.length + " chars");

        // Check if ssecurity is corrupted (too short or contains invalid Base64 characters)
        const isCorrupted = this.session.ssecurity.length < 20 || !/^[A-Za-z0-9+/=]+$/.test(this.session.ssecurity);

        if (isCorrupted) {
          this.log.warn(
            "Found corrupted session (ssecurity invalid: " + this.session.ssecurity.length + " chars), clearing for fresh login...",
          );
          this.session = {};
          this.cookieJar = new tough.CookieJar(); // Clear all cookies
          await this.saveCookies(); // Clear the saved state
          await this.login();
        } else {
          // ssecurity looks valid - try to resume session
          const sessionResumed = await this.resumeSession();
          if (!sessionResumed) {
            // Check if session was cleared (authentication error) or kept (network error)
            if (!this.session.ssecurity) {
              // Session was cleared due to authentication error - perform fresh login
              this.log.info("Session resumption failed due to authentication error, performing fresh login...");
              this.session = {};
              this.cookieJar = new tough.CookieJar(); // Clear all cookies
              await this.saveCookies(); // Clear the saved state
              await this.login();
            } else {
              // Session was kept (network error) - skip device updates and try again next interval
              this.log.warn("Session resumption failed due to network error - will retry at next update interval");
              this.setState("info.connection", false, true);
              // Don't call login() - adapter will retry validation on next update cycle
            }
          }
        }
      } else {
        // No ssecurity found - clear everything and perform fresh login
        this.log.info("No valid session found, clearing and performing fresh login...");
        this.session = {};
        this.cookieJar = new tough.CookieJar(); // Clear all cookies
        await this.saveCookies(); // Clear the saved state
        await this.login();
      }
    } else {
      this.log.info("No saved cookies found, clearing and performing fresh login...");
      this.session = {};
      this.cookieJar = new tough.CookieJar(); // Clear all cookies
      await this.login();
    }

    // Initial device fetch if we have a valid session
    if (this.session.ssecurity) {
      await this.getDeviceList();
      await this.updateDevicesViaSpec();
      await this.updateDevices();
      await this.updateCustomStates();
      await this.updateVacuumStatus();
      await this.getHome();
      await this.getActions();
    }

    // ALWAYS set up polling interval, even if initial connection failed
    // The interval will handle reconnection attempts
    this.updateInterval = setInterval(
      async () => {
        // If we have session credentials but connection is false, try to re-validate session
        const connectionState = await this.getStateAsync("info.connection");
        if (this.session.ssecurity && connectionState && !connectionState.val) {
          this.log.info("Connection lost - attempting to re-validate session...");
          const sessionResumed = await this.resumeSession();
          if (sessionResumed) {
            this.log.info("Session re-validated successfully, resuming updates");
          } else if (!this.session.ssecurity) {
            // Session was cleared due to authentication error
            this.log.warn("Session validation failed, attempting fresh login...");
            await this.login();
          } else {
            // Network error persists - skip this update cycle
            this.log.debug("Network error persists, skipping update cycle");
            return;
          }
        }

        // Only poll if we have a valid session
        if (this.session.ssecurity) {
          await this.updateDevicesViaSpec();
          await this.updateDevices();
          await this.updateCustomStates();
          await this.updateVacuumStatus();
        }
      },
      this.config.interval * 60 * 1000,
    );
    // Note: Automatic token refresh disabled - with manual QR-code login,
    // the session remains valid indefinitely (until server-side invalidation).
    // No need for periodic re-authentication.
  }
  async login() {
    // QR-Code Login (matching Python's QrCodeXiaomiCloudConnector)
    this.log.info("Starting Xiaomi Cloud Login...");

    // Clear any old session data to ensure fresh login
    this.session = {};

    // Step 1: Get QR code URL
    if (!(await this.qrLoginStep1())) {
      this.log.error("Unable to get login QR code");
      return false;
    }

    // Step 2: Display QR code and wait for scan
    if (!(await this.qrLoginStep2())) {
      this.log.error("Unable to display QR code");
      return false;
    }

    // Step 3: Wait for user to scan QR code
    if (!(await this.qrLoginStep3())) {
      this.log.error("QR code login timeout or failed");
      return false;
    }

    // Step 4: Get service token
    if (!(await this.qrLoginStep4())) {
      this.log.error("Unable to get service token");
      return false;
    }

    this.log.info("Login successful!");
    return true;
  }

  /**
   * QR-Code Login Step 1: Get QR code URL
   * Matches Python's login_step_1()
   */
  async qrLoginStep1() {
    this.log.debug("QR Login Step 1");
    const url = "https://account.xiaomi.com/longPolling/loginUrl";
    const params = {
      _qrsize: "480",
      qs: "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
      callback: "https://sts.api.io.mi.com/sts",
      _hasLogo: "false",
      sid: "xiaomiio",
      serviceParam: "",
      _locale: "en_GB",
      _dc: Date.now().toString(),
    };

    try {
      this.log.debug("Requesting QR code from: " + url);
      this.log.debug("Request params: " + JSON.stringify(params));

      const response = await this.requestClient({
        method: "get",
        url: url,
        params: params,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          Accept: "*/*",
        },
      });

      this.log.debug("QR Login Step 1 response status: " + response.status);
      this.log.debug("QR Login Step 1 response data: " + JSON.stringify(response.data));

      if (response.status === 200 && response.data) {
        // Parse response data - remove &&&START&&& prefix if present
        let data = response.data;
        if (typeof data === "string" && data.indexOf("&&&START&&&") === 0) {
          data = JSON.parse(data.replace("&&&START&&&", ""));
          this.log.debug("Parsed JSON after removing &&&START&&& prefix");
        }

        if (data.qr) {
          this.session.qrImageUrl = data.qr;
          this.session.loginUrl = data.loginUrl;
          this.session.longPollingUrl = data.lp;
          this.session.timeout = data.timeout;
          this.log.debug("QR code URLs extracted successfully");
          this.log.debug("QR Image URL: " + data.qr);
          this.log.debug("Login URL: " + data.loginUrl);
          this.log.debug("Long Polling URL: " + data.lp);
          return true;
        } else {
          this.log.error("Response data missing 'qr' field: " + JSON.stringify(data));
        }
      }
    } catch (error) {
      this.log.error("QR Login Step 1 error: " + error.message);
      if (error.response) {
        this.log.error("Response status: " + error.response.status);
        this.log.error("Response data: " + JSON.stringify(error.response.data));
      }
      this.log.debug("Error stack: " + error.stack);
    }

    return false;
  }

  /**
   * QR-Code Login Step 2: Display QR code
   * Matches Python's login_step_2()
   */
  async qrLoginStep2() {
    this.log.debug("QR Login Step 2");
    const url = this.session.qrImageUrl;
    this.log.debug("QR Image URL: " + url);

    try {
      const response = await this.requestClient({
        method: "get",
        url: url,
        responseType: "arraybuffer",
      });

      if (response.status === 200) {
        this.log.warn("════════════════════════════════════════════════════════");
        this.log.warn("  XIAOMI CLOUD LOGIN REQUIRED");
        this.log.warn("════════════════════════════════════════════════════════");
        this.log.warn("");
        this.log.warn("Please visit this URL in your browser and log in:");
        this.log.warn(this.session.loginUrl);
        this.log.warn("");
        this.log.warn("After logging in, the adapter will automatically continue.");
        this.log.warn("════════════════════════════════════════════════════════");

        return true;
      }
    } catch (error) {
      this.log.error("QR Login Step 2 error: " + error.message);
    }

    return false;
  }

  /**
   * QR-Code Login Step 3: Long-polling for QR code scan
   * Matches Python's login_step_3()
   */
  async qrLoginStep3() {
    this.log.debug("QR Login Step 3");
    const url = this.session.longPollingUrl;
    this.log.debug("Long polling URL: " + url);

    const startTime = Date.now();
    // timeout from API is in seconds, convert to milliseconds
    const timeoutMs = (this.session.timeout || this.QR_CODE_TIMEOUT) * 1000;
    this.log.info("Login valid for " + timeoutMs / 1000 + " seconds");

    // Start long polling
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Check if overall timeout exceeded BEFORE making request
      const elapsed = Date.now() - startTime;
      if (elapsed > timeoutMs) {
        this.log.error("QR code login timeout after " + elapsed / 1000 + " seconds");
        return false;
      }

      try {
        this.log.debug("Long polling attempt (elapsed: " + Math.round(elapsed / 1000) + "s / " + Math.round(timeoutMs / 1000) + "s)...");

        const response = await this.requestClient({
          method: "get",
          url: url,
          timeout: this.LONG_POLL_TIMEOUT,
        });

        this.log.debug("Long polling response status: " + response.status);

        if (response.status === 200) {
          // Parse response data - remove &&&START&&& prefix if present
          let data = response.data;
          if (typeof data === "string" && data.indexOf("&&&START&&&") === 0) {
            const jsonString = data.replace("&&&START&&&", "");
            data = JSON.parse(jsonString);
            this.log.debug("Parsed JSON after removing &&&START&&& prefix from long-polling response");
            this.log.debug("Full parsed data: " + JSON.stringify(data));
          }

          // Check if data contains the required fields
          if (data && data.userId && data.location) {
            // Success! User scanned the QR code
            this.log.info("Login completed successfully!");

            this.session.userId = data.userId;
            this.session.ssecurity = data.ssecurity;
            this.session.cUserId = data.cUserId;
            this.session.passToken = data.passToken;
            this.session.location = data.location;

            this.log.debug("User ID: " + this.session.userId);
            this.log.debug(
              "Ssecurity (length " + (this.session.ssecurity ? this.session.ssecurity.length : 0) + "): " + this.session.ssecurity,
            );
            this.log.debug("Location: " + this.session.location);

            return true;
          } else {
            // Response received but incomplete - continue polling
            this.log.debug("Received 200 but data incomplete, continuing to wait...");
            this.log.debug("Response data: " + JSON.stringify(data));
          }
        } else {
          // Non-200 status, continue polling
          this.log.debug("Received status " + response.status + ", continuing to wait for scan...");
        }
      } catch (error) {
        // Timeout is expected - continue polling
        if (error.code === "ECONNABORTED" || error.message.includes("timeout")) {
          this.log.debug("Long polling request timeout (expected), retrying...");
          continue;
        } else if (error.response) {
          // Server returned an error response
          this.log.debug("Long polling response error: " + error.response.status + " - continuing...");
          continue;
        } else {
          this.log.error("Long polling error: " + error.message);
          this.log.debug("Error details: " + JSON.stringify(error));
          // Don't fail immediately on network errors, keep trying
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait 2 seconds before retry
          continue;
        }
      }
    }
  }

  /**
   * QR-Code Login Step 4: Get service token
   * Matches Python's login_step_4()
   */
  async qrLoginStep4() {
    this.log.debug("QR Login Step 4");
    this.log.debug("Fetching service token...");

    const location = this.session.location;
    if (!location) {
      this.log.error("No location found");
      return false;
    }

    try {
      const response = await this.requestClient({
        method: "get",
        url: location,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
      });

      if (response.status === 200) {
        // Extract serviceToken from cookies
        const cookies = await this.cookieJar.getCookies(location);
        let serviceToken = null;

        for (const cookie of cookies) {
          if (cookie.key === "serviceToken") {
            serviceToken = cookie.value;
            break;
          }
        }

        // Fallback: check Set-Cookie headers
        if (!serviceToken && response.headers["set-cookie"]) {
          const setCookies = Array.isArray(response.headers["set-cookie"])
            ? response.headers["set-cookie"]
            : [response.headers["set-cookie"]];

          for (const cookieStr of setCookies) {
            if (cookieStr.includes("serviceToken=")) {
              const match = cookieStr.match(/serviceToken=([^;]+)/);
              if (match) {
                serviceToken = match[1];
                break;
              }
            }
          }
        }

        if (!serviceToken) {
          this.log.error("Failed to extract serviceToken");
          return false;
        }

        this.session.serviceToken = serviceToken;
        this.log.info("Service token obtained successfully");
        this.log.debug("Service token: " + serviceToken);

        // Install service token cookies on multiple domains (matching Python)
        const apiDomains = [
          { domain: ".api.io.mi.com", url: "https://api.io.mi.com" },
          { domain: ".io.mi.com", url: "https://io.mi.com" },
          { domain: ".mi.com", url: "https://mi.com" },
        ];

        for (const { domain, url } of apiDomains) {
          await this.cookieJar.setCookie(`serviceToken=${serviceToken}; Domain=${domain}; Path=/`, url);
          await this.cookieJar.setCookie(`yetAnotherServiceToken=${serviceToken}; Domain=${domain}; Path=/`, url);
          if (this.session.userId) {
            await this.cookieJar.setCookie(`userId=${this.session.userId}; Domain=${domain}; Path=/`, url);
          }
        }

        // Clean up temporary QR-Code URLs from session before saving
        // These are only valid for 5 minutes and should not be saved
        delete this.session.qrImageUrl;
        delete this.session.loginUrl;
        delete this.session.longPollingUrl;
        delete this.session.timeout;

        // Save cookies
        await this.saveCookies();

        // Set connection state
        this.setState("info.connection", true, true);

        return true;
      }
    } catch (error) {
      this.log.error("QR Login Step 4 error: " + error.message);
    }

    return false;
  }

  async getDeviceList() {
    this.log.info("Get devices");

    const path = "/v2/home/device_list_page";
    const data = { get_split_device: true, support_smart_home: true, accessKey: "IOS00026747c5acafc2", limit: 300 };
    const { nonce, data_rc, rc4_hash_rc, signature, signedNonce } = this.createBody(path, data);

    // Build headers with correct API headers
    const headers = await this.buildApiHeaders();

    await axios({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: headers,
      params: {
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
        ssecurity: this.session.ssecurity,
        _nonce: nonce,
      },
    })
      .then(async (res) => {
        try {
          // Python: decoded = self.decrypt_rc4(self.signed_nonce(fields["_nonce"]), response.text)
          // Create new RC4 with signedNonce for response decoding
          const rc4 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);
          res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
        } catch (error) {
          this.log.error(error);
          return;
        }
        if (res.data.code !== 0) {
          this.log.error("Error getting device list");
          this.log.error(JSON.stringify(res.data));
          return;
        }
        this.log.debug(JSON.stringify(res.data));
        if (res.data.result && res.data.result.list) {
          this.log.info(`Found ${res.data.result.list.length} devices`);
          for (const device of res.data.result.list) {
            this.log.debug(JSON.stringify(device));

            const id = device.did;

            this.deviceArray.push(device);
            this.deviceDicts[id] = device;
            const name = device.name;
            this.log.info(`Fetch device ${name} (${id})`);
            await this.setObjectNotExistsAsync(id, {
              type: "device",
              common: {
                name: name,
              },
              native: {},
            });

            this.json2iob.parse(id + ".general", device, { forceIndex: true });
          }
          await this.fetchScenes();
          await this.fetchSpecs();
          await this.fetchPlugins();

          for (const device of this.deviceArray) {
            if (this.specs[device.spec_type]) {
              this.log.debug(JSON.stringify(this.specs[device.spec_type]));
              await this.extractRemotesFromSpec(device);
            }

            // Create states from configDes
            // Note: Some devices support both spec AND custom properties (e.g., Philips lamps)
            try {
              await this.createStatesFromConfigDes(device);
            } catch (error) {
              this.log.error(`Error creating states from configDes: ${error}`);
            }
            const remoteArray = this.remoteCommands[device.model] || [];
            for (const remote of remoteArray) {
              await this.setObjectNotExistsAsync(device.did + ".remotePlugins", {
                type: "channel",
                common: {
                  name: "Remote Controls extracted from Plugin definition",
                  desc: "Not so reliable alternative remotes",
                },
                native: {},
              });
              this.setObjectNotExists(device.did + ".remotePlugins.customCommand", {
                type: "state",
                common: {
                  name: "Send Custom command via Plugin",
                  type: "mixed",
                  role: "state",
                  def: "set_level_favorite,16",
                  write: true,
                  read: true,
                },
                native: {},
              });
              let name = remote;
              let params = "";
              if (typeof remote === "object") {
                name = remote.type;
                params = remote.params;
              }
              // Replace dots with underscores to prevent folder creation
              if (typeof name === "string") {
                name = name.replace(/\./g, "_");
              }
              try {
                this.setObjectNotExists(device.did + ".remotePlugins." + name, {
                  type: "state",
                  common: {
                    name: name + " " + (params || ""),
                    type: "mixed",
                    role: "state",
                    def: false,
                    write: true,
                    read: true,
                  },
                  native: {},
                });
              } catch (error) {
                this.log.error(error);
              }
            }
          }
        }
      })
      .catch((error) => {
        this.log.error(error);
        this.log.error(error.stack);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async fetchPlugins() {
    this.log.info("Fetching Plugins");
    const path = "/v2/plugin/fetch_plugin";
    // const models = [{ model: "deerma.humidifier.jsq" }, { model: "yeelink.light.bslamp1" }];
    const models = [];
    for (const device of this.deviceArray) {
      models.push({ model: device.model });
    }

    const data = {
      accessKey: "IOS00026747c5acafc2",
      latest_req: { plugins: models, app_platform: "IOS", api_version: 10075, package_type: "", region: "zh" },
    };
    const result = await this.genericRequest(path, data);

    if (result && result.result && result.result.latest_info) {
      for (const plugin of result.result.latest_info) {
        this.log.info(`Found plugin for ${plugin.model} `);
        await this.requestClient({
          method: "get",
          url: plugin.download_url,
          responseType: "arraybuffer",
        })
          .then(async (res) => {
            try {
              const zip = new AdmZip(res.data);
              const zipEntries = zip.getEntries();
              for (const zipEntry of zipEntries) {
                if (zipEntry.entryName.includes("main.bundle")) {
                  const bundle = zip.readAsText(zipEntry);

                  // Extract methods from Protocol.Methods definition
                  // Search for "var rubyMethods = {" or "var saphireMethods = {" followed by method definitions
                  const methodsRegex = /var\s+(ruby|saphire)Methods\s*=\s*\{([^}]+)\}/gs;
                  const methodsMatch = bundle.match(methodsRegex);

                  const filteredMatches = [];

                  if (methodsMatch) {
                    // Extract all method values from the Protocol.Methods object
                    // Format: MethodName: 'method_name',
                    const methodPattern = /:\s*['"]([a-z_][a-z0-9_]{2,34})['"]/gi;

                    for (const methodBlock of methodsMatch) {
                      let methodMatch;
                      while ((methodMatch = methodPattern.exec(methodBlock)) !== null) {
                        const methodName = methodMatch[1];
                        if (!filteredMatches.includes(methodName)) {
                          filteredMatches.push(methodName);
                        }
                      }
                    }

                    this.log.debug(`Extracted ${filteredMatches.length} methods from Protocol.Methods for ${plugin.model}`);
                  }

                  // Also find direct string calls (fallback for methods not in Protocol.Methods)
                  const directCallRegex = /callMethod\s*\(\s*['"]([a-z_][a-z0-9_]{2,34})['"]/gi;
                  let directMatch;
                  while ((directMatch = directCallRegex.exec(bundle)) !== null) {
                    const methodName = directMatch[1];
                    if (!filteredMatches.includes(methodName)) {
                      filteredMatches.push(methodName);
                    }
                  }

                  // Also check switch-case patterns for additional methods
                  const regexCases = new RegExp("case.*:\\n.*type = '([a-zA-Z][a-zA-Z0-9_]{2,34})'.*\\n.*params = (.*);", "gm");
                  const matchesCases = bundle.matchAll(regexCases);

                  for (const matchCase of matchesCases) {
                    if (matchCase[1] && !filteredMatches.includes(matchCase[1])) {
                      filteredMatches.push(matchCase[1]);
                    }
                  }

                  this.remoteCommands[plugin.model] = filteredMatches;
                  this.log.info(`Found ${filteredMatches.length} remote plugin commands for ${plugin.model}`);
                  this.log.debug(`Remote plugin commands for ${plugin.model}: ${JSON.stringify(filteredMatches)}`);
                  // Note: Event extraction removed - HTTP Event Subscription (/mipush/eventsub) not supported
                  // Events require MQTT implementation (not yet available)
                  return filteredMatches;
                }
              }
            } catch (error) {
              this.log.error(error);
              this.log.error(error.stack);
              return;
            }
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }
  async fetchScenes() {
    this.log.info("Get Scenes");
    try {
      const data = { st_id: "30", api_version: 5, accessKey: "IOS00026747c5acafc2" };
      const resultData = await this.makeApiRequest("/scene/list", data, "Fetch scenes");

      this.log.debug(JSON.stringify(resultData));
      await this.setObjectNotExistsAsync("scenes", {
        type: "channel",
        common: {
          name: "Scenes",
        },
        native: {},
      });

      for (const sceneKey in resultData.result) {
        const scene = resultData.result[sceneKey];
        this.log.info(`Found scene ${scene.name} with id ${scene.us_id}`);
        this.scenes[scene.us_id] = scene;
        this.setObjectNotExists("scenes." + scene.us_id, {
          type: "state",
          common: {
            name: scene.name,
            type: "boolean",
            role: "button",
            def: false,
            write: true,
            read: true,
          },
          native: {},
        });
      }
    } catch (error) {
      // Error already logged in makeApiRequest
    }
  }
  async fetchSpecs() {
    this.log.info("Fetching Specs");
    // const models = [{ model: "deerma.humidifier.jsq" }, { model: "yeelink.light.bslamp1" }];
    const specs = [];
    for (const device of this.deviceArray) {
      // device.spec_type = "urn:miot-spec-v2:device:light:0000A001:yeelink-bslamp1:1";
      specs.push(device.spec_type);
    }
    // specs = ["urn:miot-spec-v2:device:humidifier:0000A00E:deerma-jsq:1", "urn:miot-spec-v2:device:light:0000A001:yeelink-bslamp1:1"];

    await this.requestClient({
      method: "post",
      url: "https://miot-spec.org/miot-spec-v2/instance",
      data: {
        urns: specs,
      },
    })
      .then(async (res) => {
        this.specs = res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async createStatesFromConfigDes(device) {
    for (const config of configDes) {
      if (!config.models.includes(device.model)) {
        continue;
      }

      this.log.info(`Processing ${config.props.length} custom properties from configDes for ${device.model}`);

      // Create custom channel for configDes states
      await this.setObjectNotExistsAsync(device.did + ".custom", {
        type: "channel",
        common: {
          name: "Custom Controls",
          desc: "Additional controls from configDes.js (not from device specification)",
        },
        native: {},
      });

      // Check if this is a vacuum device that supports get_status
      const isVacuumDevice = device.model && (device.model.startsWith("roborock.vacuum.") || device.model.startsWith("rockrobo.vacuum."));

      if (isVacuumDevice) {
        this.log.info(
          `Vacuum device ${device.model}: custom states will be created dynamically from get_status polling for available properties`,
        );
        this.vacuumStatusDevices.push(device.did);
        break; // Skip remaining config processing for this device
      }

      // Initialize custom properties list for polling
      this.customPropsDict[device.did] = [];

      for (const prop of config.props) {
        const propKey = prop.prop_key.replace("prop.", "").replace(/\./g, "_");

        // Determine type and role
        let type = "mixed";
        let role = "state";
        let min = undefined;
        let max = undefined;
        let states = undefined;

        if (prop.switchStatus) {
          type = "boolean";
          role = "switch";
        } else if (prop.prop_extra && prop.prop_extra.length > 0) {
          const firstValue = prop.prop_extra[0].value;
          const lastValue = prop.prop_extra[prop.prop_extra.length - 1].value;

          if (!isNaN(firstValue) && !isNaN(lastValue)) {
            type = "number";
            role = "level";
            min = parseInt(firstValue);
            max = parseInt(lastValue);
          } else if (prop.prop_extra.length <= 10) {
            // Create states object for value list
            states = {};
            for (const extra of prop.prop_extra) {
              states[extra.value] = extra.desc.en || extra.desc.zh_CN;
            }
          }
        }

        // Get name from prop_name
        const name = prop.prop_name ? prop.prop_name.en || prop.prop_name.zh_CN : propKey;

        // Get method from cards
        let method = null;
        if (config.cards && config.cards.card_items) {
          for (const card of config.cards.card_items) {
            if (card.prop_key === prop.prop_key && card.operation && card.operation.length > 0) {
              method = card.operation[0].method;
              break;
            }
          }
        }

        this.log.debug(`Creating state ${propKey} with method ${method}`);

        await this.extendObjectAsync(device.did + ".custom." + propKey, {
          type: "state",
          common: {
            name: name,
            type: type,
            role: role,
            min: min,
            max: max,
            states: states,
            unit: prop.prop_unit,
            write: true,
            read: true,
          },
          native: {
            prop_key: prop.prop_key,
            method: method,
            supportType: prop.supportType,
            did: device.did,
            model: device.model,
          },
        });

        // Add property key to polling list (for get_prop, skip for vacuum devices)
        if (!isVacuumDevice) {
          this.customPropsDict[device.did].push({
            prop_key: prop.prop_key,
            stateName: propKey,
          });
        }
      }

      break; // Only process first matching config
    }
  }
  async extractRemotesFromSpec(device) {
    const spec = this.specs[device.spec_type];
    this.log.info(`Extracting status and remotes from spec for ${device.model} ${spec.description}`);
    this.log.info("You can get detailed information about status and remotes here: http://www.merdok.org/miotspec/?model=" + device.model);
    let siid = 0;
    this.specStatusDict[device.did] = [];

    this.specActionsToIdDict[device.did] = {};
    this.specPropsToIdDict[device.did] = {};
    this.specEventsToIdDict[device.did] = {};

    // Initialize tracking for used state names (first occurrence gets clean name)
    if (!this.usedStateNames[device.did]) {
      this.usedStateNames[device.did] = {};
    }

    // Track if we need to create status/remote folders
    let hasReadOnlyProps = false;
    let hasWritableProps = false;

    // First pass: check what types of properties exist
    for (const service of spec.services) {
      const typeArray = service.type.split(":");
      const serviceTypeName = typeArray[3];
      if (serviceTypeName === "device-information") continue;

      if (service.properties) {
        for (const property of service.properties) {
          const write = property.access.includes("write");
          if (write) {
            hasWritableProps = true;
          } else {
            hasReadOnlyProps = true;
          }
        }
      }
      if (service.actions && service.actions.length > 0) {
        hasWritableProps = true;
      }
    }

    // Create folders based on what exists
    if (hasReadOnlyProps) {
      await this.setObjectNotExistsAsync(device.did + ".status", {
        type: "channel",
        common: {
          name: "Status",
          desc: "Read-only status values from device specification",
        },
        native: {},
      });
    }

    if (hasWritableProps) {
      await this.setObjectNotExistsAsync(device.did + ".remote", {
        type: "channel",
        common: {
          name: "Remote Controls",
          desc: "Writable properties and actions from device specification",
        },
        native: {},
      });
    }

    // Second pass: create states with appropriate names
    for (const service of spec.services) {
      if (service.iid) {
        siid = service.iid;
      } else {
        siid++;
      }
      const typeArray = service.type.split(":");
      const serviceTypeName = typeArray[3];

      // Skip device-information service
      if (serviceTypeName === "device-information") {
        continue;
      }

      try {
        // Process Properties
        let piid = 0;
        if (service.properties) {
          for (const property of service.properties) {
            if (property.iid) {
              piid = property.iid;
            } else {
              piid++;
            }

            const write = property.access.includes("write");
            const folder = write ? "remote" : "status"; // Read-only -> status/, writable -> remote/

            // Process property
            const property_data = { property, piid, siid, service, folder, write };

            const typeName = property_data.property.type.split(":")[3].replace(/\./g, "_");

            // First occurrence gets clean name, subsequent ones get service prefix
            let uniqueName;
            if (!this.usedStateNames[device.did][typeName]) {
              uniqueName = typeName;
              this.usedStateNames[device.did][typeName] = true;
            } else {
              uniqueName = `${property_data.service.description.toLowerCase().replace(/\s+/g, "-")}-${typeName}`;
              this.log.debug(`Adding prefix to '${typeName}' from ${property_data.service.description} due to conflict`);
            }

            const [type, role] = this.getRole(property_data.property.format, property_data.write, property_data.property["value-range"]);
            this.log.debug(
              `Found ${property_data.write ? "writable" : "read-only"} property for ${device.model} ${property_data.service.description} ${property_data.property.description}`,
            );

            const states = {};
            if (property_data.property["value-list"]) {
              for (const value of property_data.property["value-list"]) {
                states[value.value] = value.description;
              }
            }
            let unit;
            if (property_data.property.unit && property_data.property.unit !== "none") {
              unit = property_data.property.unit === "percentage" ? "%" : property_data.property.unit;
            } else if (property_data.property["value-range"] && property_data.property["value-range"].length >= 2) {
              // Auto-detect percentage: range 0-100 or 1-100
              const min = property_data.property["value-range"][0];
              const max = property_data.property["value-range"][1];
              if ((min === 0 || min === 1) && max === 100) {
                unit = "%";
              }
            }

            const propertyPath = property_data.folder + "." + uniqueName;
            await this.extendObjectAsync(device.did + "." + propertyPath, {
              type: "state",
              common: {
                name: property_data.service.description + " - " + property_data.property.description,
                type: type,
                role: role,
                unit: unit,
                min: property_data.property["value-range"] ? property_data.property["value-range"][0] : undefined,
                max: property_data.property["value-range"] ? property_data.property["value-range"][1] : undefined,
                states: property_data.property["value-list"] ? states : undefined,
                write: property_data.write,
                read: true,
              },
              native: {
                siid: property_data.siid,
                piid: property_data.piid,
                did: device.did,
                model: device.model,
                name: property_data.service.description + " " + property_data.property.description,
                type: property_data.property.type,
                access: property_data.property.access,
              },
            });

            // Add all readable properties to polling
            if (property_data.property.access.includes("read")) {
              this.specStatusDict[device.did].push({
                did: device.did,
                siid: property_data.siid,
                code: 0,
                piid: property_data.piid,
                updateTime: 0,
              });
            }

            this.specPropsToIdDict[device.did][property_data.siid + "-" + property_data.piid] = device.did + "." + propertyPath;
          }
        }

        // Process Actions -> all go to remote/ (actions are always writable)
        let aiid = 0;
        if (service.actions && service.actions.length > 0) {
          for (const action of service.actions) {
            if (action.iid) {
              aiid = action.iid;
            } else {
              aiid++;
            }
            const remote = {
              siid: siid,
              aiid: aiid,
              did: device.did,
              model: device.model,
              name: service.description + " " + action.description,
              type: action.type,
              access: action.access,
            };
            const typeName = action.type.split(":")[3].replace(/\./g, "_");

            // First occurrence gets clean name, subsequent ones get service prefix
            let uniqueName;
            if (!this.usedStateNames[device.did][typeName]) {
              uniqueName = typeName;
              this.usedStateNames[device.did][typeName] = true;
            } else {
              uniqueName = `${service.description.toLowerCase().replace(/\s+/g, "-")}-${typeName}`;
              this.log.debug(`Adding prefix to '${typeName}' from ${service.description} due to conflict`);
            }

            // Actions should be buttons, not switches (executed with one click)
            let type = "boolean";
            let role = "button";
            this.log.debug(`Found action for ${device.model} ${service.description} ${action.description}`);

            const states = {};
            if (action["value-list"]) {
              for (const value of action["value-list"]) {
                states[value.value] = value.description;
              }
            }

            let def;
            if (action.in && action.in.length) {
              type = "string";
              role = "text";
              def = JSON.stringify(action.in);
              const inNames = action.in.map((inParam) => {
                const prop = service.properties?.find((p) => p.iid === inParam);
                return prop ? prop.description : inParam;
              });
              remote.name += ` in[${inNames.join(", ")}]`;
            }

            if (action.out && action.out.length) {
              const outNames = action.out.map((outParam) => {
                const prop = service.properties?.find((p) => p.iid === outParam);
                return prop ? prop.description : outParam;
              });
              remote.name += ` out[${outNames.join(", ")}]`;
            }

            let unit;
            if (action.unit && action.unit !== "none") {
              unit = action.unit;
            }

            // All actions go into global remote/ folder
            const actionPath = "remote." + uniqueName;
            this.setObjectNotExists(device.did + "." + actionPath, {
              type: "state",
              common: {
                name: service.description + " - " + action.description,
                type: type,
                role: role,
                unit: unit,
                min: action["value-range"] ? action["value-range"][0] : undefined,
                max: action["value-range"] ? action["value-range"][1] : undefined,
                states: action["value-list"] ? states : undefined,
                write: true,
                read: true,
                def: def != null ? def : undefined,
              },
              native: {
                siid: siid,
                aiid: aiid,
                did: device.did,
                model: device.model,
                in: action.in || [],
                out: action.out || [],
                name: service.description + " " + action.description,
                type: action.type,
                access: action.access,
              },
            });
            this.specActionsToIdDict[device.did][service.iid + "-" + action.iid] = device.did + "." + actionPath;
          }
        }

        // Process Events -> all go to global events/ folder
        if (service.events && service.events.length > 0) {
          for (const event of service.events) {
            const typeName = event.type.split(":")[3].replace(/\./g, "_");

            // First occurrence gets clean name, subsequent ones get service prefix
            let uniqueName;
            if (!this.usedStateNames[device.did][typeName]) {
              uniqueName = typeName;
              this.usedStateNames[device.did][typeName] = true;
            } else {
              uniqueName = `${service.description.toLowerCase().replace(/\s+/g, "-")}-${typeName}`;
              this.log.debug(`Adding prefix to '${typeName}' from ${service.description} due to conflict`);
            }

            const eventPath = "status." + uniqueName;

            await this.setObjectNotExistsAsync(device.did + "." + eventPath, {
              type: "state",
              common: {
                name: service.description + " - " + event.description,
                type: "boolean",
                role: "indicator",
                write: false,
                read: true,
              },
              native: {
                siid: siid,
                eiid: event.iid,
                did: device.did,
                model: device.model,
                name: service.description + " " + event.description,
                type: event.type,
                arguments: event.arguments || [],
              },
            });

            // Store event path for updates
            this.specEventsToIdDict[device.did][service.iid + "-" + event.iid] = device.did + "." + eventPath;
          }
        }
      } catch (error) {
        this.log.error("Error while extracting spec for " + device.model);
        this.log.error(error);
        this.log.error(error.stack);
        this.log.info(JSON.stringify(service));
      }
    }
  }

  async genericRequest(path, data) {
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
    const cookieHeader = await this.buildCookieHeader();

    return await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: {
        ...this.header,
        Cookie: cookieHeader,
      },
      params: {
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
        ssecurity: this.session.ssecurity,
      },
      data: "",
    })
      .then(async (res) => {
        try {
          const result = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
          this.log.debug(JSON.stringify(result));
          return result;
        } catch (error) {
          this.log.error(error);
          return;
        }
      })
      .catch((error) => {
        this.log.error(error);
        this.log.error(error.stack);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getHome() {
    const path = "/homeroom/gethome";
    const data = { fetch_share: true, accessKey: "IOS00026747c5acafc2", app_ver: 7, limit: 300 };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
    const cookieHeader = await this.buildCookieHeader();

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: {
        ...this.header,
        Cookie: cookieHeader,
      },
      params: {
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
        ssecurity: this.session.ssecurity,
      },
      data: "",
    })
      .then(async (res) => {
        try {
          const result = rc4.decode(res.data).replace("&&&START&&&", "");
          this.log.debug(result);
          this.home = JSON.parse(result).result;
        } catch (error) {
          this.log.error(error);
          return;
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getActions() {
    if (!this.home || this.home.homelist.length === 0) {
      this.log.info("No home found, skipping getActions");
      return;
    }
    const path = "/scene/tplv2";
    const data = {
      home_id: parseInt(this.home.homelist[0].id),
      accessKey: "IOS00026747c5acafc2",
      owner_uid: this.session.userId,
      limit: 300,
    };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
    const headers = await this.buildApiHeaders();

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: headers,
      params: {
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
        ssecurity: this.session.ssecurity,
      },
      data: "",
    })
      .then(async (res) => {
        try {
          const result = JSON.parse(rc4.decode(res.data)).result;
          // Actions data available in result.tpl but not currently used
          // Each device has: model, name, value.action_list with sa_id, payload.command, etc.
          this.log.debug(`Fetched ${result.tpl.length} action templates from Xiaomi Cloud`);
        } catch (error) {
          this.log.error(error);
          return;
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async buildApiHeaders() {
    // Build headers matching Python's execute_api_call_encrypted
    const cookieHeader = await this.buildCookieHeader();
    return {
      "User-Agent": this.header["User-Agent"],
      "Content-Type": "application/x-www-form-urlencoded",
      "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
      "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
      Cookie: cookieHeader,
    };
  }

  async buildCookieHeader() {
    // Python sends cookies as a dict to requests.post(cookies={...})
    // requests combines this with session cookies automatically
    // We need to manually build the cookie header from ALL cookies in the jar
    // plus the explicit ones that Python sets

    const targetDomain = "https://" + this.config.region + "api.io.mi.com";
    const allCookies = await this.cookieJar.getCookies(targetDomain);

    // Start with cookies from jar
    const cookieMap = {};
    for (const cookie of allCookies) {
      cookieMap[cookie.key] = cookie.value;
    }

    // Override/add the explicit cookies that Python sets
    // (these match what Python passes in the cookies parameter)
    cookieMap["userId"] = this.session.userId || cookieMap["userId"];
    cookieMap["serviceToken"] = this.session.serviceToken || cookieMap["serviceToken"];
    cookieMap["yetAnotherServiceToken"] = this.session.serviceToken || cookieMap["yetAnotherServiceToken"];
    cookieMap["locale"] = "de_DE";
    cookieMap["timezone"] = "GMT+01:00";
    cookieMap["is_daylight"] = "0";
    cookieMap["dst_offset"] = "3600000";
    cookieMap["channel"] = "MI_APP_STORE";

    this.log.debug(`buildCookieHeader: Using userId=${cookieMap["userId"]} (session.userId=${this.session.userId})`);
    this.log.debug(`buildCookieHeader: Using serviceToken=${cookieMap["serviceToken"]?.substring(0, 30)}...`);

    if (!cookieMap["serviceToken"]) {
      this.log.error("buildCookieHeader: serviceToken is missing!");
      this.log.error("Session keys: " + Object.keys(this.session).join(", "));
      this.log.error("Available cookies: " + Object.keys(cookieMap).join(", "));
    }

    // Build cookie header string
    return Object.entries(cookieMap)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  createBody(path, data) {
    if (!this.session.ssecurity) {
      this.log.error("Cannot create request body: ssecurity is missing from session!");
      this.log.error("Session keys: " + Object.keys(this.session).join(", "));
      throw new Error("ssecurity is required but not found in session");
    }

    // Python does: url.split("com")[1].replace("/app/", "/")
    // So /app/v2/home/device_list_page becomes /v2/home/device_list_page
    const normalizedPath = path.replace("/app/", "/");

    this.log.debug(
      `Creating body for ${path} (normalized: ${normalizedPath}) with ssecurity: ${this.session.ssecurity.substring(0, 20)}...`,
    );
    const nonce = this.generateNonce();
    const signedNonce = this.signedNonce(this.session.ssecurity, nonce);

    // Python algorithm matches exactly:
    // 1. params["rc4_hash__"] = generate_enc_signature(url, method, signed_nonce, params)
    //    where params = {"data": {...}} (unencrypted)
    // 2. for k, v in params.items(): params[k] = encrypt_rc4(signed_nonce, v)
    //    This encrypts BOTH data AND rc4_hash__!
    // 3. params.update({"signature": generate_enc_signature(url, method, signed_nonce, params), ...})
    //    Signature calculated with encrypted params

    // Step 1: Calculate rc4_hash__ with UNENCRYPTED data param
    const dataStr = JSON.stringify(data);
    let signatureParams = ["POST", normalizedPath, `data=${dataStr}`, signedNonce];
    this.log.debug(`Step 1 - Signature params (unencrypted): POST & ${normalizedPath} & data=... & signedNonce`);
    const rc4_hash = crypto.createHash("sha1").update(signatureParams.join("&"), "utf8").digest("base64");
    this.log.debug(`Step 1 - rc4_hash (unencrypted): ${rc4_hash}`);

    // Step 2: Encrypt data
    const rc4_1 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);
    const data_rc = rc4_1.encode(dataStr);
    this.log.debug(`Step 2a - Encrypted data (first 50 chars): ${data_rc.substring(0, 50)}`);

    // Step 2b: Encrypt rc4_hash__ (Python does this in the for loop)
    const rc4_2 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);
    const rc4_hash_rc = rc4_2.encode(rc4_hash);
    this.log.debug(`Step 2b - Encrypted rc4_hash: ${rc4_hash_rc}`);

    // Step 3: Calculate final signature with ENCRYPTED params (both data and rc4_hash__)
    signatureParams = ["POST", normalizedPath, `data=${data_rc}`, `rc4_hash__=${rc4_hash_rc}`, signedNonce];
    this.log.debug(`Step 3 - Signature params (encrypted): POST & ${normalizedPath} & data=... & rc4_hash__=... & signedNonce`);
    const signature = crypto.createHash("sha1").update(signatureParams.join("&"), "utf8").digest("base64");
    this.log.debug(`Step 3 - Final signature: ${signature}`);

    // Create RC4 instance for decoding the response
    const rc4 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);

    return { nonce, data_rc, rc4_hash_rc, signature, signedNonce, rc4 };
  }
  getRole(element, write, valueRange) {
    if (!element) {
      return ["boolean", "switch"];
    }
    if (element === "bool" && !write) {
      return ["boolean", "indicator"];
    }
    if (element === "bool" && write) {
      return ["boolean", "switch"];
    }
    if ((element.indexOf("int") !== -1 || valueRange) && !write) {
      return ["number", "value"];
    }
    if ((element.indexOf("int") !== -1 || valueRange) && write) {
      return ["number", "level"];
    }

    return ["string", "text"];
  }
  async updateDevices() {
    // Universal status sources that work for all devices:
    // 1. Miot Spec (status/ + remote/) - handled in getStatus
    // 2. configDes.js (custom/) - handled in getCustomProperties
    // 3. Plugin commands (remotePlugins/) - handled in createStates
    // 4. Events (events/) - handled below

    for (const device of this.deviceArray) {
      const deviceStatusArray = [];

      // Note: HTTP Event Subscription (/mipush/eventsub) removed - not supported by Xiaomi API
      // Events require MQTT subscription (not yet implemented)
      // For now, devices only support status polling via spec properties

      for (const element of deviceStatusArray) {
        const data = JSON.parse(JSON.stringify(element.props).replace("$DID", device.did));
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(element.url, data);
        const cookieHeader = await this.buildCookieHeader();
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + element.url,
          headers: {
            ...this.header,
            Cookie: cookieHeader,
          },
          params: {
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
            ssecurity: this.session.ssecurity,
          },
          data: "",
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.code !== 0) {
              if (res.data.code === -8 || res.data.code === -2) {
                // Mark device as unsupported for plugin status
                if (element.path === "pluginStatus" && res.data.code === -8) {
                  this.unsupportedPluginStatus[device.did] = true;
                  this.log.debug(`Device ${device.name} (${device.did}) does not support plugin status. Will not retry.`);
                } else {
                  this.log.debug(`Error getting ${element.desc} for ${device.name} (${device.did}) with ${JSON.stringify(element.props)}`);
                  this.log.debug(JSON.stringify(res.data));
                }
                return;
              }
              this.log.warn(`Error getting ${element.desc} for ${device.name} (${device.did}) with ${JSON.stringify(element.props)}`);
              this.log.warn(JSON.stringify(res.data));
              return;
            }

            this.log.debug(JSON.stringify(res.data));

            // Handle plugin status response
            if (element.path === "pluginStatus") {
              if (res.data.result && Array.isArray(res.data.result)) {
                for (const evt of res.data.result) {
                  if (evt.siid && evt.eiid) {
                    const eventPath = this.specEventsToIdDict[device.did][evt.siid + "-" + evt.eiid];
                    if (eventPath) {
                      this.log.info(`Event triggered: ${eventPath}`);
                      // Set event to true, then auto-reset after 5 seconds
                      await this.setStateAsync(eventPath, true, true);
                      setTimeout(() => {
                        this.setState(eventPath, false, true);
                      }, this.EVENT_AUTO_RESET_DELAY);
                    }
                  }
                }
              }
              return;
            }

            const resultData = this.parseResponse(res, element.url, device.did);
            this.log.debug(JSON.stringify(resultData));
            if (!resultData) {
              return;
            }

            this.json2iob.parse(device.did + "." + element.path, resultData, {
              forceIndex: true,
              write: true,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.warn(element.path + " receive 401 error - session may be invalid");
                this.setState("info.connection", false, true);
                return;
              }
            }
            if (error.code === "ENOTFOUND" || error.code === "ETIMEDOUT") {
              this.log.debug(error);
              return;
            }

            this.log.error(element.url);
            this.log.error(error);
            error.stack && this.log.error(error.stack);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }
  async updateCustomStates() {
    if (!this.customPropsDict) {
      return;
    }

    for (const device of this.deviceArray) {
      if (!this.customPropsDict[device.did] || this.customPropsDict[device.did].length === 0) {
        continue;
      }

      this.log.debug(`Polling ${this.customPropsDict[device.did].length} custom properties for ${device.name} (${device.did})`);

      // Split properties into chunks that fit within the character JSON limit
      // Some devices have a character limit for the params array
      const MAX_JSON_LENGTH = this.MAX_JSON_PARAMS_LENGTH;
      const chunks = [];
      let currentChunk = [];

      for (const prop of this.customPropsDict[device.did]) {
        const testChunk = [...currentChunk, prop];
        const testKeys = testChunk.map((p) => p.prop_key);
        const jsonLength = JSON.stringify(testKeys).length;

        if (jsonLength > MAX_JSON_LENGTH && currentChunk.length > 0) {
          // Current chunk is full, start a new one
          chunks.push(currentChunk);
          currentChunk = [prop];
        } else {
          currentChunk.push(prop);
        }
      }

      // Add the last chunk if not empty
      if (currentChunk.length > 0) {
        chunks.push(currentChunk);
      }

      this.log.debug(`Split ${this.customPropsDict[device.did].length} properties into ${chunks.length} chunk(s) for polling`);

      // Poll each chunk
      for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex++) {
        const chunk = chunks[chunkIndex];
        const propKeys = chunk.map((p) => p.prop_key);
        const jsonLength = JSON.stringify(propKeys).length;

        this.log.debug(`Chunk ${chunkIndex + 1}/${chunks.length}: ${propKeys.length} properties, JSON length: ${jsonLength} chars`);

        const url = "/home/rpc/" + device.did;
        const data = {
          id: 0,
          method: "get_prop",
          accessKey: "IOS00026747c5acafc2",
          params: propKeys,
        };

        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        const cookieHeader = await this.buildCookieHeader();

        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + url,
          headers: {
            ...this.header,
            Cookie: cookieHeader,
          },
          params: {
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
            ssecurity: this.session.ssecurity,
          },
          data: "",
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
            } catch (error) {
              this.log.error(error);
              return;
            }

            if (res.data.code !== 0) {
              if (res.data.code === -8 || res.data.code === -2 || res.data.code === -3) {
                // Code -8: Device doesn't support get_prop - mark it to prevent future attempts
                if (res.data.code === -8) {
                  this.customPropsDict[device.did] = []; // Clear custom properties list
                  this.log.debug(`Device ${device.name} (${device.did}) does not support get_prop for custom properties. Will not retry.`);
                } else {
                  this.log.debug(
                    `Error getting custom properties for ${device.name} (${device.did}): ${res.data.message || "unknown error"}`,
                  );
                  this.log.debug(JSON.stringify(res.data));
                }
                return;
              }
              this.log.warn(`Error getting custom properties for ${device.name} (${device.did})`);
              this.log.warn(JSON.stringify(res.data));
              return;
            }

            // Check for device-level errors (even when code is 0)
            if (res.data.error && res.data.error.code && res.data.error.code !== 0) {
              if (res.data.error.code === -9999 || res.data.error.code === -3) {
                this.log.debug(`Device timeout for ${device.name} (${device.did}): ${res.data.error.message || "timeout"}`);
                return;
              }
              this.log.debug(`Device error for ${device.name} (${device.did}): ${JSON.stringify(res.data.error)}`);
              return;
            }

            this.log.debug(`Custom properties response: ${JSON.stringify(res.data)}`);

            // Update states with received values
            if (res.data.result && Array.isArray(res.data.result)) {
              for (let i = 0; i < res.data.result.length && i < chunk.length; i++) {
                const propInfo = chunk[i];
                let value = res.data.result[i];
                const statePath = device.did + ".custom." + propInfo.stateName;

                // Convert string values to appropriate types for ioBroker states (only if not null)
                if (value !== null && value !== undefined) {
                  const stateObj = await this.getObjectAsync(statePath);
                  if (stateObj?.common.type === "boolean" && typeof value === "string") {
                    value = value === "on" || value === "true" || value === "1";
                  } else if (stateObj?.common.type === "number" && typeof value === "string") {
                    value = parseFloat(value);
                  }
                }

                this.log.debug(`Updating ${statePath} to ${value} (${propInfo.prop_key})`);
                await this.setStateAsync(statePath, value, true);
              }
            }
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                this.log.info("Custom properties polling received 401 error. Refresh Token in 60 seconds");
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);
                return;
              }
            }
            if (error.code === "ENOTFOUND" || error.code === "ETIMEDOUT") {
              this.log.debug(error);
              return;
            }
            this.log.error(`Error polling custom properties for ${device.name}: ${error.message}`);
            this.log.debug(error.stack);
          });
      } // end chunk loop
    } // end device loop
  }

  async updateVacuumStatus() {
    if (!this.vacuumStatusDevices || this.vacuumStatusDevices.length === 0) {
      return;
    }

    for (const did of this.vacuumStatusDevices) {
      const device = this.deviceDicts[did];
      if (!device) {
        continue;
      }

      this.log.debug(`Polling vacuum status for ${device.name} (${device.did})`);

      const url = "/home/rpc/" + device.did;
      const data = {
        id: 0,
        method: "get_status",
        accessKey: "IOS00026747c5acafc2",
        params: [],
      };

      const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
      const cookieHeader = await this.buildCookieHeader();

      await this.requestClient({
        method: "post",
        url: "https://" + this.config.region + "api.io.mi.com/app" + url,
        headers: {
          ...this.header,
          Cookie: cookieHeader,
        },
        params: {
          _nonce: nonce,
          data: data_rc,
          rc4_hash__: rc4_hash_rc,
          signature: signature,
          ssecurity: this.session.ssecurity,
        },
        data: "",
      })
        .then(async (res) => {
          try {
            res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
          } catch (error) {
            this.log.error(error);
            return;
          }

          if (res.data.code !== 0) {
            if (res.data.code === -8 || res.data.code === -2 || res.data.code === -3) {
              this.log.debug(`Error getting vacuum status for ${device.name} (${device.did}): ${res.data.message || "unknown error"}`);
              this.log.debug(JSON.stringify(res.data));
              return;
            }
            this.log.warn(`Error getting vacuum status for ${device.name} (${device.did})`);
            this.log.warn(JSON.stringify(res.data));
            return;
          }

          // Check for device-level errors (even when code is 0)
          if (res.data.error && res.data.error.code && res.data.error.code !== 0) {
            if (res.data.error.code === -9999 || res.data.error.code === -3) {
              this.log.debug(`Device timeout for ${device.name} (${device.did}): ${res.data.error.message || "timeout"}`);
              return;
            }
            this.log.debug(`Device error for ${device.name} (${device.did}): ${JSON.stringify(res.data.error)}`);
            return;
          }

          this.log.debug(`Vacuum status response: ${JSON.stringify(res.data)}`);

          // Parse get_status response - it returns an array with a single status object
          if (res.data.result && Array.isArray(res.data.result) && res.data.result.length > 0) {
            const status = res.data.result[0];

            // Update all fields from get_status response
            // Check if configDes definition exists for this model
            const config = configDes.find((c) => c.models && c.models.includes(device.model));
            const hasConfigDes = config && config.props && config.props.length > 0;

            // Create states dynamically for fields from API response
            for (const [field, value] of Object.entries(status)) {
              if (value === null || value === undefined) {
                continue;
              }

              const statePath = device.did + ".custom." + field;

              // Try to get metadata from configDes
              const propDef = config?.props?.find((p) => p.prop_key === `prop.${field}`);

              // If configDes exists but this field is not defined there, skip it
              if (hasConfigDes && !propDef) {
                this.log.debug(`Skipping ${statePath} - not defined in configDes for ${device.model}`);
                continue;
              }

              // Check if state exists
              const stateObj = await this.getObjectAsync(statePath);

              // Determine if we need to create/update the state
              const needsUpdate = !stateObj || (propDef && (stateObj.common.unit !== propDef.prop_unit || !stateObj.native?.prop_key));

              if (needsUpdate) {
                // Determine proper ioBroker type from value
                let ioType = "mixed";
                if (typeof value === "boolean") {
                  ioType = "boolean";
                } else if (typeof value === "number") {
                  ioType = "number";
                } else if (typeof value === "string") {
                  ioType = "string";
                }

                // Create or update state with configDes definition (if available) or fallback values
                await this.extendObjectAsync(statePath, {
                  type: "state",
                  common: {
                    name: propDef?.prop_name?.en || propDef?.prop_name?.zh_CN || field,
                    type: ioType,
                    role: "value",
                    unit: propDef?.prop_unit,
                    read: true,
                    write: false,
                  },
                  native: {
                    prop_key: propDef?.prop_key || `prop.${field}`,
                    did: device.did,
                    model: device.model,
                  },
                });
              }

              // Apply ratio conversion if defined in configDes
              let convertedValue = value;
              if (propDef?.ratio && typeof value === "number") {
                convertedValue = value * propDef.ratio;
                // Round to 2 decimals for area, 0 for time
                if (field === "clean_area") {
                  convertedValue = Math.round(convertedValue * 100) / 100;
                } else {
                  convertedValue = Math.round(convertedValue);
                }
              }

              this.log.debug(`Updating ${statePath} to ${convertedValue}`);
              await this.setStateAsync(statePath, convertedValue, true);
            }
          }
        })
        .catch((error) => {
          if (error.response) {
            if (error.response.status === 401) {
              this.log.info("Vacuum status polling received 401 error. Refresh Token in 60 seconds");
              this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
              this.refreshTokenTimeout = setTimeout(() => {
                this.refreshToken();
              }, 1000 * 60);
              return;
            }
          }
          if (error.code === "ENOTFOUND" || error.code === "ETIMEDOUT") {
            this.log.debug(error);
            return;
          }
          this.log.error(`Error polling vacuum status for ${device.name}: ${error.message}`);
          this.log.debug(error.stack);
        });
    } // end device loop
  }

  async updateDevicesViaSpec() {
    for (const device of this.deviceArray) {
      const url = "/v2/miotspec/prop/get"; // v2 API
      if (this.specStatusDict[device.did]) {
        const data = {
          datasource: 1, // v2 API: 1=Cloud, 2=Local
          params: this.specStatusDict[device.did],
        };
        this.log.debug(`Get status for ${device.did} via spec`);
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        const cookieHeader = await this.buildCookieHeader();
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + url,
          headers: {
            ...this.header,
            Cookie: cookieHeader,
          },
          params: {
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
            ssecurity: this.session.ssecurity,
          },
          data: "",
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.code !== 0) {
              if (res.data.code === -8 || res.data.code === -2) {
                this.log.debug(`Error getting spec update for ${device.name} (${device.did}) with ${JSON.stringify(data)}`);
                this.log.debug(JSON.stringify(res.data));
                return;
              }
              this.log.info(`Error getting spec update for ${device.name} (${device.did}) with ${JSON.stringify(data)}`);
              this.log.debug(JSON.stringify(res.data));
              return;
            }
            this.log.debug(JSON.stringify(res.data));
            for (const element of res.data.result) {
              const path = this.specPropsToIdDict[device.did][element.siid + "-" + element.piid];
              if (path) {
                if (element.code !== undefined && element.code !== 0) {
                  // Only log non -704220043 errors (device doesn't support property)
                  if (element.code !== -704220043) {
                    this.log.debug(`Property ${path} returned error code ${element.code}`);
                  }
                } else if (element.value !== undefined) {
                  this.log.debug(`Set ${path} to ${element.value}`);
                  this.setState(path, element.value, true);
                } else {
                  this.log.debug(`Property ${path} has no value in response`);
                }
              } else {
                this.log.debug(`No path mapping found for siid=${element.siid}, piid=${element.piid}`);
              }
            }
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(url + " receive 401 error. Refresh Token in 60 seconds");
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }

              this.log.debug(url);
              this.log.debug(error);
              error.stack && this.log.debug(error.stack);
              error.response && this.log.debug(JSON.stringify(error.response.data));
              return;
            }

            this.log.debug(error);
            this.log.debug(url);
            this.log.debug(JSON.stringify(error));
          });
      }
    }
  }

  parseResponse(res, url, did) {
    if (Array.isArray(res.data.result)) {
      // For plugin responses like: {"result": [0, {prop1: val1, prop2: val2, ...}]}
      // Return the properties object directly (result[1]), not wrapped in {status: ...}
      return res.data.result[1] || res.data.result[0];
    }
    if (!res.data.result) {
      try {
        return JSON.parse(res.data);
      } catch (error) {
        return res.data;
      }
    }
    let resultData = res.data.result[did];
    if (!resultData) {
      this.log.debug(`No data for ${did} `);
      return;
    }
    if (url === "/v2/device/batchgetdatas") {
      resultData = res.data.result[did]["event.status"];
      if (!resultData) {
        this.log.debug(`No data for ${did} `);
        return;
      }
      resultData = JSON.parse(resultData.value)[0];
    }
    if (res.data.result.out) {
      const base64String = res.data.result.out[0];
      resultData = JSON.parse(Buffer.from(base64String, "base64").toString("utf8"));
      resultData = resultData.result[0];
    }
    return resultData;
  }
  async refreshToken() {
    // Note: With manual QR-code authentication, automatic token refresh is not possible.
    // The session remains valid indefinitely until server-side invalidation.
    // If a 401 error occurs, the user needs to manually restart the adapter to trigger a new login.
    this.log.warn("Session appears to be invalid (401 error)");
    this.log.warn("Please check your adapter configuration and restart the adapter to re-authenticate");
    this.setState("info.connection", false, true);
  }

  generateNonce() {
    const buf = Buffer.allocUnsafe(12);
    buf.write(crypto.randomBytes(8).toString("hex"), 0, "hex");
    buf.writeInt32BE(Date.now() / 60000, 8);
    return buf.toString("base64");
  }

  signedNonce(ssecret, nonce) {
    const s = Buffer.from(ssecret, "base64");
    const n = Buffer.from(nonce, "base64");
    return crypto.createHash("sha256").update(s).update(n).digest("base64");
  }
  randomString(length) {
    let result = "";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }

  /**
   * Generic API request helper with RC4 encryption
   * @param {string} path - API endpoint path
   * @param {Object} data - Request data to encrypt
   * @param {string} errorContext - Context for error logging
   * @returns {Promise<Object>} Decrypted response data
   */
  async makeApiRequest(path, data, errorContext = "API request") {
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
    const cookieHeader = await this.buildCookieHeader();

    try {
      const res = await this.requestClient({
        method: "post",
        url: "https://" + this.config.region + "api.io.mi.com/app" + path,
        headers: {
          ...this.header,
          Cookie: cookieHeader,
        },
        params: {
          _nonce: nonce,
          data: data_rc,
          rc4_hash__: rc4_hash_rc,
          signature: signature,
          ssecurity: this.session.ssecurity,
        },
        data: "",
      });

      const result = rc4.decode(res.data).replace("&&&START&&&", "");
      return JSON.parse(result);
    } catch (error) {
      this.log.error(`${errorContext} failed: ${error.message}`);
      if (error.response?.data) {
        this.log.debug(`Response: ${JSON.stringify(error.response.data)}`);
      }
      throw error;
    }
  }

  /**
   * Resume session from saved cookies and session state
   */
  async resumeSession() {
    try {
      this.log.debug("Attempting to resume session...");

      // Check if we have all required session data from QR-Code login
      if (!this.session || !this.session.ssecurity || !this.session.userId || !this.session.serviceToken) {
        this.log.debug("Missing required session data (ssecurity, userId, or serviceToken)");
        return false;
      }

      // Try to make a test API call to see if session is still valid
      this.log.debug("Testing existing session validity...");

      try {
        const path = "/v2/home/device_list_page";
        const data = { get_split_device: true, support_smart_home: true, accessKey: "IOS00026747c5acafc2", limit: 1 };
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
        const headers = await this.buildApiHeaders();

        const response = await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + path,
          headers: headers,
          params: {
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
            ssecurity: this.session.ssecurity,
          },
          data: "",
        });

        const result = JSON.parse(rc4.decode(response.data).replace("&&&START&&&", ""));

        if (result.code === 0) {
          this.log.info("Existing session is still valid - resuming without re-login");
          this.setState("info.connection", true, true);
          return true;
        } else {
          this.log.info("Session test failed with code: " + result.code + " - fresh login required");
          return false;
        }
      } catch (error) {
        if (error.response && error.response.status === 401) {
          this.log.info("Session expired (401 error) - fresh login required");
          // Clear session only on authentication errors
          this.session = {};
          this.cookieJar = new tough.CookieJar();
        } else if (error.response && error.response.status === 400) {
          this.log.info("Session invalid (400 error - invalid signature) - fresh login required");
          // Clear session only on authentication errors
          this.session = {};
          this.cookieJar = new tough.CookieJar();
        } else if (
          !error.response &&
          (error.code === "EBUSY" || error.code === "ETIMEDOUT" || error.code === "ENOTFOUND" || error.code === "ECONNREFUSED")
        ) {
          // Network connectivity issues - keep session and try again later
          this.log.warn(
            "Network connectivity issue during session validation (" +
              error.code +
              ": " +
              error.message +
              ") - keeping session and will retry",
          );
          return false; // Session validation failed due to network, but don't clear credentials
        } else {
          this.log.debug("Session test failed: " + error.message);
          // For unknown errors, clear session to prevent issues
          this.session = {};
          this.cookieJar = new tough.CookieJar();
        }
        return false;
      }
    } catch (error) {
      this.log.warn("Error during session resumption: " + error.message);
      return false;
    }
  }

  /**
   * Delete all device objects from ioBroker object tree
   * Called when account or region changes
   */
  async deleteAllDevices() {
    try {
      this.log.info("Deleting all device objects...");

      // Get all objects under this adapter instance
      const objects = await this.getAdapterObjectsAsync();

      let deletedCount = 0;
      for (const id in objects) {
        // Skip auth channel and info states
        if (id.includes(".auth.") || id.includes(".info.")) {
          continue;
        }

        // Delete device objects (type: device, channel, or state under devices)
        const idParts = id.split(".");
        if (idParts.length >= 3) {
          // Format: mihome-cloud.0.DEVICE_ID.*
          const potentialDeviceId = idParts[2];

          // Skip if this is not a device (auth, info, etc.)
          if (potentialDeviceId !== "auth" && potentialDeviceId !== "info") {
            try {
              await this.delObjectAsync(id, { recursive: true });
              deletedCount++;
              this.log.debug("Deleted object: " + id);
            } catch (err) {
              this.log.debug("Could not delete " + id + ": " + err.message);
            }
          }
        }
      }

      // Clear device arrays
      this.deviceArray = [];
      this.deviceDicts = {};

      this.log.info("Deleted " + deletedCount + " device objects");
    } catch (error) {
      this.log.error("Error deleting devices: " + error.message);
    }
  }

  /**
   * Save cookies to ioBroker state for persistence across adapter restarts
   */
  async saveCookies() {
    try {
      const cookieData = {
        cookies: this.cookieJar.toJSON(),
        deviceId: this.deviceId,
        session: this.session, // Save session data for resumption
        timestamp: Date.now(),
        userId: this.session.userId, // Save userId to detect account changes
        region: this.config.region, // Save region to detect region changes
      };

      // Create auth channel if it doesn't exist
      await this.setObjectNotExistsAsync("auth", {
        type: "channel",
        common: {
          name: "Authentication Data",
        },
        native: {},
      });

      // Create session state object if it doesn't exist
      await this.extendObject(this.cookieStateId, {
        type: "state",
        common: {
          name: "Authentication Session Data (Cookies and Session)",
          type: "string",
          role: "json",
          read: true,
          write: false,
        },
        native: {},
      });

      // Save cookies to state
      await this.setStateAsync(this.cookieStateId, JSON.stringify(cookieData), true);
      this.log.debug("Cookies and session saved successfully to state");
    } catch (error) {
      this.log.warn("Failed to save cookies: " + error.message);
    }
  }

  /**
   * Load cookies from ioBroker state to restore session after adapter restart
   */
  async loadCookies() {
    try {
      const state = await this.getStateAsync(this.cookieStateId);
      if (!state || !state.val) {
        this.log.debug("No saved cookies found");
        return false;
      }

      const cookieData = JSON.parse(String(state.val));

      // Check if userId or region has changed - devices need to be deleted
      // Note: userId comes from Xiaomi server after QR login, not from config
      const accountChanged = cookieData.userId && this.session.userId && cookieData.userId !== this.session.userId;
      const regionChanged = cookieData.region && cookieData.region !== this.config.region;

      if (accountChanged) {
        // Account changed: Delete devices AND invalidate session (need fresh login)
        this.log.warn("Account changed!");
        this.log.warn("  Old userId: " + cookieData.userId);
        this.log.warn("  New userId: " + this.session.userId);
        this.log.warn("  Deleting all old device objects...");
        await this.deleteAllDevices();
        this.log.warn("  Clearing old session and performing fresh login...");
        return false;
      }

      if (regionChanged) {
        // Region changed: Delete devices but KEEP session (session is valid across regions)
        this.log.warn("Region changed!");
        this.log.warn("  Old region: " + cookieData.region);
        this.log.warn("  New region: " + this.config.region);
        this.log.warn("  Deleting all old device objects...");
        await this.deleteAllDevices();
        this.log.info("  Session will be resumed with new region");
        // Update stored region to new value
        cookieData.region = this.config.region;
        // Continue loading the session (don't return false)
      }

      // Log for debugging: Show which account's session is being loaded
      if (cookieData.username) {
        this.log.info("Loading session for account: " + cookieData.username);
      }

      // Additional validation: Check if userId in session matches expected pattern
      // If username changed but wasn't saved before, userId will be different after fresh login
      if (cookieData.session && cookieData.session.userId) {
        this.log.debug("Session contains userId: " + cookieData.session.userId);
      }

      // Restore deviceId to maintain consistency
      if (cookieData.deviceId) {
        this.deviceId = cookieData.deviceId;
      }

      // Restore session data if available
      if (cookieData.session) {
        this.session = cookieData.session;

        // Remove any temporary QR-Code URLs that may have been saved
        // These are only valid for 5 minutes and should never be restored
        delete this.session.qrImageUrl;
        delete this.session.loginUrl;
        delete this.session.longPollingUrl;
        delete this.session.timeout;

        this.log.debug("Session data restored from state");
      }

      // Restore cookies to jar using proper tough-cookie method
      this.cookieJar = tough.CookieJar.fromJSON(cookieData.cookies);
      this.log.debug("Cookies and session loaded successfully from state");
      return true;
    } catch (error) {
      this.log.warn("Failed to load cookies: " + error.message);
      return false;
    }
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const folder = id.split(".")[3];
        let command = id.split(".")[4];
        this.log.debug(`Receive command ${command} for ${deviceId} in folder ${folder} with value ${state.val} `);
        if (command) {
          command = command.split("-")[0];
        }
        if (id.split(".")[4] === "Refresh") {
          this.updateDevicesViaSpec();
          return;
        }
        //{"id":0,"method":"app_start","params":[{"clean_mop":0}]}

        const stateObject = await this.getObjectAsync(id);
        let params = [];
        if (stateObject && stateObject.common.type === "mixed") {
          try {
            params = JSON.parse(String(state.val));
          } catch (error) {
            this.log.debug(error);
          }
        }
        let url = "/v2/device/batchgetdatas";
        let data = [{ did: deviceId, props: ["event.status"], accessKey: "IOS00026747c5acafc2" }];

        if (deviceId === "scenes") {
          url = "/scene/start";
          data = { us_id: folder, accessKey: "IOS00026747c5acafc2" };
        }
        this.log.debug(`Search for ${deviceId} in ${JSON.stringify(this.deviceDicts)}`);

        if (
          (this.deviceDicts[deviceId] && this.remoteCommands[this.deviceDicts[deviceId].model]) ||
          id.includes("remotePlugins.customCommand")
        ) {
          url = "/home/rpc/" + deviceId;
          params = state.val;
          if (id.includes("remotePlugins.customCommand")) {
            const stateArray = String(state.val).replace(/ /g, "").split(",");
            command = stateArray[0];
            params = stateArray[1];
          }
          try {
            data = { id: 0, method: command, accessKey: "IOS00026747c5acafc2", params: JSON.parse(`[${JSON.stringify(params)}]`) };
          } catch (error) {
            this.log.error(error);
          }
          this.log.debug(`Send remote plugin command ${JSON.stringify(data)} to ${deviceId}`);
        }
        if (id.includes(".custom.")) {
          url = "/home/rpc/" + deviceId;
          const stateObject = await this.getObjectAsync(id);
          if (stateObject && stateObject.native && stateObject.native.method) {
            command = stateObject.native.method;
            params = state.val;

            // Handle boolean values (convert to on/off)
            if (typeof state.val === "boolean") {
              params = state.val ? "on" : "off";
            }

            try {
              data = { id: 0, method: command, accessKey: "IOS00026747c5acafc2", params: JSON.parse(`[${JSON.stringify(params)}]`) };
            } catch (error) {
              this.log.error(error);
            }
            this.log.debug(`Send configDes command ${command} with params ${params} to ${deviceId}`);
          } else {
            this.log.error(`No method found for ${id}`);
            return;
          }
        }
        // Handle remote states (writable properties and actions)
        if (id.includes(".remote.")) {
          // Check if it's a property (has piid) or action (has aiid)
          if (stateObject && stateObject.native.piid) {
            // It's a property
            url = "/v2/miotspec/prop/set"; // v2 API
            data = {
              params: [{ did: deviceId, siid: stateObject.native.siid, piid: stateObject.native.piid, value: state.val }],
            };
          } else if (stateObject && stateObject.native.aiid) {
            // It's an action
            url = "/v2/miotspec/action"; // v2 API
            data = {
              params: { did: deviceId, siid: stateObject.native.siid, aiid: stateObject.native.aiid },
            };
            if (typeof state.val !== "boolean") {
              try {
                data.params["in"] = JSON.parse(String(state.val));
              } catch (error) {
                this.log.error(error);
                return;
              }
            }
          }
        }
        this.log.debug(`Send: ${JSON.stringify(data)} to ${deviceId} via ${url}`);
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        const cookieHeader = await this.buildCookieHeader();
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + url,
          headers: {
            ...this.header,
            Cookie: cookieHeader,
          },
          params: {
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
            ssecurity: this.session.ssecurity,
          },
          data: "",
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data));
              this.log.debug(JSON.stringify(res.data));
            } catch (error) {
              this.log.error(error);
              return;
            }

            if (res.data.code !== 0) {
              this.log.error("Error setting device state");
              this.log.error(JSON.stringify(res.data));
              return;
            }
            if (res.data.result && res.data.result.length > 0) {
              res.data = res.data.result[0];
            }
            this.log.debug(JSON.stringify(res.data));
            if (!res.data.result) {
              return;
            }
            const result = res.data.result;
            if (result.out) {
              const path = this.specActionsToIdDict[result.did][result.siid + "-" + result.aiid];
              this.log.debug(path);
              const stateObject = await this.getObjectAsync(path);
              if (stateObject && stateObject.native.out) {
                const out = stateObject.native.out;
                for (const outItem of out) {
                  const index = out.indexOf(outItem);
                  const outPath = this.specPropsToIdDict[result.did][result.siid + "-" + outItem];
                  await this.setStateAsync(outPath, result.out[index], true);
                  this.log.info("Set " + outPath + " to " + result.out[index]);
                }
              } else {
                this.log.debug(JSON.stringify(result.out));
              }
            }
          })
          .catch(async (error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        // Refresh device state after command
        this.refreshTimeout = setTimeout(async () => {
          this.log.debug("Update devices");
          await this.updateDevices();
          await this.updateDevicesViaSpec();
        }, 10000); // 10 seconds delay
      } else {
        const resultDict = {
          auto_target_humidity: "setTargetHumidity",
          enabled: "setSwitch",
          display: "setDisplay",
          child_lock: "setChildLock",
          level: "setLevel-wind",
        };
        const idArray = id.split(".");
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split(".")[2];
        if (resultDict[stateName]) {
          const value = state.val;
          await this.setStateAsync(deviceId + ".remote." + resultDict[stateName], value, true);
        }
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new MihomeCloud(options);
} else {
  // otherwise start the instance directly
  new MihomeCloud();
}
