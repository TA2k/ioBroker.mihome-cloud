"use strict";

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const qs = require("qs");
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
    this.deviceArray = [];
    this.deviceDicts = {};
    this.local = "de";
    this.deviceId = this.randomString(40);
    this.remoteCommands = {};
    this.specStatusDict = {};
    this.specPropsToIdDict = {};
    this.specActiosnToIdDict = {};
    this.scenes = {};
    this.events = {};
    this.json2iob = new Json2iob(this);

    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
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
    if (!this.config.username || !this.config.password) {
      this.log.error("Please set username and password in the instance settings");
      return;
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
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");

    // Try to load saved cookies first
    this.log.info("Attempting to load saved cookies...");
    const cookiesLoaded = await this.loadCookies();

    if (cookiesLoaded) {
      this.log.info("Cookies loaded, attempting to resume session...");
      // Try to resume session - if it fails, perform fresh login
      const sessionResumed = await this.resumeSession();
      if (!sessionResumed) {
        this.log.info("Session resumption failed, performing fresh login...");
        await this.login();
      }
    } else {
      this.log.info("No saved cookies found, performing fresh login...");
      await this.login();
    }

    if (this.session.ssecurity) {
      await this.getDeviceList();
      await this.updateDevicesViaSpec();
      await this.updateDevices();
      await this.listLocal();
      await this.getHome();
      await this.getActions();
      this.updateInterval = setInterval(
        async () => {
          await this.updateDevicesViaSpec();
          await this.updateDevices();
        },
        this.config.interval * 60 * 1000,
      );
    }
    this.refreshTokenInterval = setInterval(
      () => {
        this.refreshToken();
      },
      12 * 60 * 60 * 1000,
    );
  }
  async login() {
    // Set essential cookies for authentication
    await this.cookieJar.setCookie("sdkVersion=accountsdk-18.8.15; path=/; domain=mi.com", "https://mi.com");
    await this.cookieJar.setCookie("sdkVersion=accountsdk-18.8.15; path=/; domain=xiaomi.com", "https://xiaomi.com");
    await this.cookieJar.setCookie("deviceId=" + this.deviceId + "; path=/; domain=mi.com", "https://mi.com");
    await this.cookieJar.setCookie("deviceId=" + this.deviceId + "; path=/; domain=xiaomi.com", "https://xiaomi.com");

    if (await this.loginStep1()) {
      if (await this.loginStep2()) {
        if (await this.loginStep3()) {
          return true;
        } else {
          this.log.error("Unable to get service token");
        }
      } else {
        this.log.error("Invalid login or password");
      }
    } else {
      this.log.error("Invalid username");
    }
    return false;
  }

  async loginStep1() {
    this.log.debug("Login Step 1");
    const url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true";
    const headers = {
      "User-Agent": "APP/com.xiaomi.mihome APPV/10.5.201",
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: `userId=${this.config.username}; sdkVersion=accountsdk-18.8.15; deviceId=${this.deviceId};`,
    };

    const response = await this.requestClient({
      method: "get",
      url: url,
      headers: headers,
    })
      .then((res) => {
        this.log.debug("&&&START&&&" + JSON.stringify(res.data));
        if (res.data.indexOf("&&&START&&&") === 0) {
          const data = res.data.replace("&&&START&&&", "");
          return JSON.parse(data);
        }
        return {};
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return {};
      });

    if (response && response.ssecurity) {
      // Already logged in
      this.session = response;
      return true;
    } else if (response && response._sign) {
      this.session = { _sign: response._sign };
      return true;
    }

    return false;
  }

  async loginStep2() {
    this.log.debug("Login Step 2");
    const url = "https://account.xiaomi.com/pass/serviceLoginAuth2";
    const headers = {
      "User-Agent": "APP/com.xiaomi.mihome APPV/10.5.201",
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: `sdkVersion=accountsdk-18.8.15; deviceId=${this.deviceId}; pass_ua=web; uLocale=de_DE;`,
    };

    const fields = {
      sid: "xiaomiio",
      hash: crypto.createHash("md5").update(this.config.password).digest("hex").toUpperCase(),
      callback: "https://sts.api.io.mi.com/sts",
      qs: "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
      user: this.config.username,
      _sign: this.session._sign,
      _json: "true",
    };

    const call = `${url}?${qs.stringify(fields)}`;

    const response = await this.requestClient({
      method: "post",
      url: call,
      headers: headers,
      data: null,
    })
      .then((res) => {
        this.log.debug("&&&START&&&" + JSON.stringify(res.data));
        if (res.data.indexOf("&&&START&&&") === 0) {
          const data = res.data.replace("&&&START&&&", "");
          return JSON.parse(data);
        }
        return {};
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return {};
      });

    // Handle captcha if required
    if (response && response.captchaUrl && response.captchaUrl !== null) {
      this.log.info("Captcha required for login, please use following url:");
      this.log.info("https://account.xiaomi.com" + response.captchaUrl);
      this.log.info("Please open the URL above and solve the captcha.");
      this.log.info("The adapter will automatically retry login every 30 seconds until successful.");

      // Set shorter retry intervals for captcha
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.refreshTokenTimeout = setTimeout(() => {
        this.log.info("Retrying login after captcha...");
        this.refreshToken();
      }, 30 * 1000); // Retry every 30 seconds

      return false;
    }

    // Handle two-factor authentication
    if (response && response.notificationUrl) {
      this.log.info("Two-factor authentication required, please use following url:");
      this.log.info(response.notificationUrl);
      this.log.info("Please open the URL above and complete the verification.");
      this.log.info("After completing verification, the adapter will automatically retry...");

      // Save session state for 2FA resumption after potential restart
      this.session = {
        ssecurity: response.ssecurity,
        userId: response.userId,
        cUserId: response.cUserId,
        passToken: response.passToken,
        location: response.location,
        code: response.code,
        notificationUrl: response.notificationUrl, // Save 2FA URL for reference
      };

      // Save cookies and session state so we can resume after restart
      await this.saveCookies();

      // Set retry timer for 2FA - user completes verification and adapter retries
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.refreshTokenTimeout = setTimeout(() => {
        this.log.info("Retrying login after 2FA...");
        this.refreshToken();
      }, 30 * 1000); // Retry every 30 seconds

      return false;
    }

    // Check for successful login
    if (response && response.ssecurity && response.ssecurity.length > 4) {
      this.session = {
        ssecurity: response.ssecurity,
        userId: response.userId,
        cUserId: response.cUserId,
        passToken: response.passToken,
        location: response.location,
        code: response.code,
      };

      return true;
    }

    // Handle other error cases
    if (response && response.code) {
      this.log.error("Login failed with code: " + response.code);
      if (response.description) {
        this.log.error("Description: " + response.description);
      }
    }

    return false;
  }

  async loginStep3() {
    this.log.debug("Login Step 3");
    const headers = {
      "User-Agent": "APP/com.xiaomi.mihome APPV/10.5.201",
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: `sdkVersion=accountsdk-18.8.15; deviceId=${this.deviceId};`,
    };

    const response = await this.requestClient({
      method: "get",
      url: this.session.location,
      headers: headers,
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.setState("info.connection", true, true);
        this.log.info("Login successful");

        // Extract service token from response headers (example.js approach)
        const setCookie = res.headers["set-cookie"] || [];
        const serviceTokenCookie = setCookie.find((c) => c.includes("serviceToken"));
        const serviceToken = serviceTokenCookie ? serviceTokenCookie.split("=")[1].split(";")[0] : null;

        if (!serviceToken) {
          this.log.error("Service token not found in response headers");
          return false;
        }

        // Set required cookies for API calls
        await this.cookieJar.setCookie("serviceToken=" + serviceToken + "; path=/; domain=api.io.mi.com", "https://api.io.mi.com");
        await this.cookieJar.setCookie("userId=" + this.session.userId + "; path=/; domain=api.io.mi.com", "https://api.io.mi.com");

        // Save cookies after complete authentication (including 2FA if required)
        await this.saveCookies();

        return true;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return false;
      });

    return response;
  }

  async getDeviceList() {
    this.log.info("Get devices");
    const path = "/v2/home/device_list_page";
    const data = { get_split_device: true, support_smart_home: true, accessKey: "IOS00026747c5acafc2", limit: 300 };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
    })
      .then(async (res) => {
        try {
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
            try {
              for (const config of configDes) {
                if (config.models.includes(device.model)) {
                  this.log.info(`Found ${device.model} (${device.name}) in configDes with ${config.props.length} properties `);
                  for (const prop of config.props) {
                    this.log.debug(prop.prop_key);
                  }
                }
              }
            } catch (error) {
              this.log.error(error);
            }
          }
          await this.fetchScenes();
          await this.fetchSpecs();
          await this.fetchPlugins();

          for (const device of this.deviceArray) {
            if (this.specs[device.spec_type]) {
              this.log.debug(JSON.stringify(this.specs[device.spec_type]));
              await this.extractRemotesFromSpec(device);
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
              try {
                this.setObjectNotExists(device.did + ".remotePlugins." + name, {
                  type: "state",
                  common: {
                    name: name + " " + params || "",
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
                  const regex = new RegExp("(?<=Method\\(.).*?(?=.,)", "gm");
                  const matches = bundle.match(regex);
                  let filteredMatches = [];
                  if (matches) {
                    filteredMatches = matches.filter((match) => match.length < 35);
                    if (filteredMatches.length != matches.length) {
                      this.log.warn("Remote commmands too long for " + plugin.model);
                      this.log.warn("Please report this url to the developer: " + plugin.download_url);
                    }
                  }
                  const regexCases = new RegExp("case.*:\\n.*type = '(.*)'.*\\n.*params = (.*);", "gm");
                  const matchesCases = bundle.matchAll(regexCases);

                  for (const match of matchesCases) {
                    if (match[1] && match[1].length < 35) {
                      filteredMatches.push({ type: match[1], params: match[2] });
                    }
                  }

                  this.remoteCommands[plugin.model] = filteredMatches;
                  const regexEvents = new RegExp("(?<=subscribeMessages\\().*?(?=\\))", "gm");
                  const eventMatches = bundle.match(regexEvents);
                  if (eventMatches) {
                    this.events[plugin.model] = eventMatches[0].replace(/'/g, "").split(", ");
                  }
                  this.log.info(`Found ${matches && matches.length} remote commands for ${plugin.model}`);
                  this.log.debug(`Remote commands for ${plugin.model}: ${JSON.stringify(matches)}`);
                  const eventLength = this.events[plugin.model] ? this.events[plugin.model].length : 0;
                  this.log.info(`Found ${eventLength} remote events for ${plugin.model}`);
                  return matches;
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
    const path = "/scene/list";
    const data = { st_id: "30", api_version: 5, accessKey: "IOS00026747c5acafc2" };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
    })
      .then(async (res) => {
        try {
          res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
        } catch (error) {
          this.log.error(error);
          return;
        }
        this.log.debug(JSON.stringify(res.data));
        await this.setObjectNotExistsAsync("scenes", {
          type: "channel",
          common: {
            name: "Scenes",
          },
          native: {},
        });
        for (const sceneKey in res.data.result) {
          const scene = res.data.result[sceneKey];
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
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
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
  async extractRemotesFromSpec(device) {
    const spec = this.specs[device.spec_type];
    this.log.info(`Extracting remotes from spec for ${device.model} ${spec.description}`);
    this.log.info("You can detailed information about status and remotes here: http://www.merdok.org/miotspec/?model=" + device.model);
    let siid = 0;
    this.specStatusDict[device.did] = [];

    this.specActiosnToIdDict[device.did] = {};
    this.specPropsToIdDict[device.did] = {};
    for (const service of spec.services) {
      if (service.iid) {
        siid = service.iid;
      } else {
        siid++;
      }
      const typeArray = service.type.split(":");
      if (typeArray[3] === "device-information") {
        continue;
      }
      if (!service.properties) {
        this.log.warn(`No properties for ${device.model} ${service.description} cannot extract information`);
        continue;
      }

      try {
        let piid = 0;
        for (const property of service.properties) {
          if (property.iid) {
            piid = property.iid;
          } else {
            piid++;
          }
          const remote = {
            siid: siid,
            piid: piid,
            did: device.did,
            model: device.model,
            name: service.description + " " + property.description + " " + service.iid + "-" + property.iid,
            type: property.type,
            access: property.access,
          };
          const typeName = property.type.split(":")[3];
          let path = "status";
          let write = false;

          if (property.access.includes("write")) {
            path = "remote";
            write = true;
          }

          const [type, role] = this.getRole(property.format, write, property["value-range"]);
          this.log.debug(`Found remote for ${device.model} ${service.description} ${property.description}`);

          await this.setObjectNotExistsAsync(device.did + "." + path, {
            type: "channel",
            common: {
              name: "Remote Controls extracted from Spec definition",
            },
            native: {},
          });
          const states = {};
          if (property["value-list"]) {
            for (const value of property["value-list"]) {
              states[value.value] = value.description;
            }
          }
          let unit;
          if (property.unit && property.unit !== "none") {
            unit = property.unit;
          }
          await this.extendObjectAsync(device.did + "." + path + "." + typeName, {
            type: "state",
            common: {
              name: remote.name || "",
              type: type,
              role: role,
              unit: unit,
              min: property["value-range"] ? property["value-range"][0] : undefined,
              max: property["value-range"] ? property["value-range"][1] : undefined,
              states: property["value-list"] ? states : undefined,
              write: write,
              read: true,
            },
            native: {
              siid: siid,
              piid: piid,
              did: device.did,
              model: device.model,
              name: service.description + " " + property.description,
              type: property.type,
              access: property.access,
            },
          });

          if (property.access.includes("notify")) {
            this.specStatusDict[device.did].push({
              did: device.did,
              siid: remote.siid,
              code: 0,
              piid: remote.piid,
              updateTime: 0,
            });
          }
          this.specPropsToIdDict[device.did][remote.siid + "-" + remote.piid] = device.did + "." + path + "." + typeName;
        }
        //extract actions
        let aiid = 0;
        if (service.actions) {
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
              name: service.description + " " + action.description + " " + service.iid + "-" + action.iid,
              type: action.type,
              access: action.access,
            };
            const typeName = action.type.split(":")[3];

            const path = "remote";
            const write = true;

            let [type, role] = this.getRole(action.format, write, action["value-range"]);
            this.log.debug(`Found actions for ${device.model} ${service.description} ${action.description}`);

            await this.extendObjectAsync(device.did + "." + path, {
              type: "channel",
              common: {
                name: "Remote Controls extracted from Spec definition",
              },
              native: {},
            });
            const states = {};
            if (action["value-list"]) {
              for (const value of action["value-list"]) {
                states[value.value] = value.description;
              }
            }
            let def;
            if (action.in.length) {
              remote.name = remote.name + " in[";

              for (const inParam of action.in) {
                type = "string";
                role = "text";
                def = JSON.stringify(action.in);
                const prop = service.properties.filter((obj) => {
                  return obj.iid === inParam;
                });
                if (prop.length > 0) {
                  remote.name = remote.name + prop[0].description + "";
                }
                if (action.in.indexOf(inParam) !== action.in.length - 1) {
                  remote.name = remote.name + ",";
                }
              }

              remote.name = remote.name + "]";
            }

            if (action.out.length) {
              remote.name = remote.name + " out[";

              for (const outParam of action.out) {
                const prop = service.properties.filter((obj) => {
                  return obj.iid === outParam;
                });
                if (prop.length > 0) {
                  remote.name = remote.name + prop[0].description;
                }
                if (action.out.indexOf(outParam) !== action.out.length - 1) {
                  remote.name = remote.name + ",";
                }
              }
              remote.name = remote.name + "]";
            }
            let unit;
            if (action.unit && action.unit !== "none") {
              unit = action.unit;
            }
            this.setObjectNotExists(device.did + "." + path + "." + typeName, {
              type: "state",
              common: {
                name: remote.name || "",
                type: type,
                role: role,
                unit: unit,
                min: action["value-range"] ? action["value-range"][0] : undefined,
                max: action["value-range"] ? action["value-range"][1] : undefined,
                states: action["value-list"] ? states : undefined,
                write: write,
                read: true,
                def: def != null ? def : undefined,
              },
              native: {
                siid: siid,
                aiid: aiid,
                did: device.did,
                model: device.model,
                in: action.in,
                out: action.out,
                name: service.description + " " + action.description,
                type: action.type,
                access: action.access,
              },
            });
            this.specActiosnToIdDict[device.did][service.iid + "-" + action.iid] = device.did + "." + path + "." + typeName;
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

    return await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
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

  async listLocal() {
    const path = "/v2/home/local_device_list";
    const data = { accessKey: "IOS00026747c5acafc2" };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
    })
      .then(async (res) => {
        try {
          this.log.debug(rc4.decode(res.data).replace("&&&START&&&", ""));
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
  async getHome() {
    const path = "/homeroom/gethome";
    const data = { fetch_share: true, accessKey: "IOS00026747c5acafc2", app_ver: 7, limit: 300 };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
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
  async gerProducts() {
    const path = "/v2/plugin/get_config_info_new";
    const data = { accessKey: "IOS00026747c5acafc2" };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
    })
      .then(async (res) => {
        try {
          const result = rc4.decode(res.data).replace("&&&START&&&", "");
          this.log.debug(result);
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

    await this.requestClient({
      method: "post",
      url: "https://" + this.config.region + "api.io.mi.com/app" + path,
      headers: this.header,
      data: qs.stringify({
        _nonce: nonce,
        data: data_rc,
        rc4_hash__: rc4_hash_rc,
        signature: signature,
      }),
    })
      .then(async (res) => {
        try {
          const result = JSON.parse(rc4.decode(res.data)).result;
          for (const device of result.tpl) {
            this.log.debug(device.model);
            this.log.debug(JSON.stringify(device.value.action_list));
          }
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

  createBody(path, data) {
    const nonce = this.generateNonce();
    const signedNonce = this.signedNonce(this.session.ssecurity, nonce);
    let params = ["POST", path, `data=${JSON.stringify(data)}`, signedNonce];
    const rc4 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);
    const rc4_hash = crypto.createHash("sha1").update(params.join("&"), "utf8").digest("base64");
    const data_rc = rc4.encode(JSON.stringify(data));
    const rc4_hash_rc = rc4.encode(rc4_hash);
    params = ["POST", path, `data=${data_rc}`, `rc4_hash__=${rc4_hash_rc}`, signedNonce];
    const signature = crypto.createHash("sha1").update(params.join("&"), "utf8").digest("base64");
    return { nonce, data_rc, rc4_hash_rc, signature, rc4 };
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
    let statusArray = [
      {
        url: "/v2/device/batchgetdatas",
        path: "statusEvent",
        desc: "Status of the device",
        props: [{ did: "$DID", props: ["event.status"], accessKey: "IOS00026747c5acafc2" }],
      },
      {
        url: "/miotspec/action",
        path: "statusAction",
        desc: "Status of the device",
        props: {
          accessKey: "IOS00026747c5acafc2",
          params: {
            did: "$DID",
            siid: 7,
            in: [Buffer.from(JSON.stringify({ id: 0, method: "get_prop", params: ["get_status"] })).toString("base64")],
            aiid: 1,
          },
        },
      },
    ];

    for (const device of this.deviceArray) {
      if (this.remoteCommands[device.model]) {
        if (this.remoteCommands[device.model][0] && !this.remoteCommands[device.model][0].includes("get")) {
          continue;
        }
        statusArray = [
          {
            url: "/home/rpc/" + device.did,
            path: "statusPlugin",
            desc: "Status of the device via Plugin",
            props: {
              id: 0,
              method: this.remoteCommands[device.model][0],
              accessKey: "IOS00026747c5acafc2",
              params: [],
            },
          },
          // {
          //   url: "/mipush/eventsub",
          //   path: "events",
          //   desc: "Events of the device",
          //   props: {
          //     expire: 10,
          //     method: this.events[device.model],
          //     did: "$DID",
          //     client: 1,
          //     subid: "0",
          //     accessKey: "IOS00026747c5acafc2",
          //     pid: 0,
          //   },
          // },
        ];
      }
      for (const element of statusArray) {
        const data = JSON.parse(JSON.stringify(element.props).replace("$DID", device.did));
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(element.url, data);
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + element.url,
          headers: this.header,
          data: qs.stringify({
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
          }),
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.code !== 0) {
              if (res.data.code === -8) {
                this.log.debug(`Error getting ${element.desc} for ${device.name} (${device.did}) with ${JSON.stringify(element.props)}`);
                return;
              }
              this.log.warn(`Error getting ${element.desc} for ${device.name} (${device.did}) with ${JSON.stringify(element.props)}`);
              this.log.warn(JSON.stringify(res.data));
              return;
            }

            this.log.debug(JSON.stringify(res.data));
            const resultData = this.parseResponse(res, element.url, device.did);
            this.log.debug(JSON.stringify(resultData));
            if (!resultData) {
              return;
            }

            const forceIndex = true;
            const preferedArrayName = null;

            this.json2iob.parse(device.did + "." + element.path, resultData, {
              forceIndex: forceIndex,
              write: true,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
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

            this.log.error(element.url);
            this.log.error(error);
            error.stack && this.log.error(error.stack);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }
  async updateDevicesViaSpec() {
    for (const device of this.deviceArray) {
      const url = "/miotspec/prop/get";
      if (this.specStatusDict[device.did]) {
        const data = { type: 3, accessKey: "IOS00026747c5acafc2", params: this.specStatusDict[device.did] };
        this.log.debug(`Get status for ${device.did} via spec`);
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + url,
          headers: this.header,
          data: qs.stringify({
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
          }),
        })
          .then(async (res) => {
            try {
              res.data = JSON.parse(rc4.decode(res.data).replace("&&&START&&&", ""));
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.code !== 0) {
              if (res.data.code === -8) {
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
                this.log.debug(`Set ${path} to ${element.value}`);
                if (element.value != null) {
                  this.setState(path, element.value, true);
                }
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
      return { status: res.data.result[1] };
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
    this.log.debug("Refresh token");
    try {
      const loginSuccess = await this.login();
      if (!loginSuccess) {
        this.log.warn("Token refresh failed, will retry in 5 minutes");
        this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
        this.refreshTokenTimeout = setTimeout(
          () => {
            this.refreshToken();
          },
          5 * 60 * 1000,
        ); // Retry in 5 minutes
      }
    } catch (error) {
      this.log.error("Error during token refresh:", error);
      this.setState("info.connection", false, true);
    }
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
   * Resume session from saved cookies and session state
   */
  async resumeSession() {
    try {
      this.log.debug("Attempting to resume session...");

      // Check if we have a saved session with location (ready for step 3)
      if (this.session && this.session.location && this.session.ssecurity) {
        this.log.info("Found saved session with location, attempting step 3...");

        // Try to complete step 3 with saved session
        if (await this.loginStep3()) {
          this.log.info("Session resumed successfully after 2FA completion");
          return true;
        } else {
          this.log.warn("Step 3 failed during session resumption");
          return false;
        }
      }

      // If we have session data but no location, try to continue from step 2
      if (this.session && this.session.ssecurity && !this.session.location) {
        this.log.info("Found partial session, checking if 2FA was completed...");

        // Try step 2 again to see if 2FA was completed
        if (await this.loginStep2()) {
          if (await this.loginStep3()) {
            this.log.info("Session resumed successfully after 2FA completion");
            return true;
          }
        }

        this.log.info("2FA not yet completed, will continue retrying...");
        return false;
      }

      // Try to make a test API call to see if session is still valid
      if (this.session && this.session.ssecurity) {
        this.log.debug("Testing existing session validity...");

        try {
          const path = "/v2/home/device_list_page";
          const data = { get_split_device: true, support_smart_home: true, accessKey: "IOS00026747c5acafc2", limit: 1 };
          const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);

          const response = await this.requestClient({
            method: "post",
            url: "https://" + this.config.region + "api.io.mi.com/app" + path,
            headers: this.header,
            data: qs.stringify({
              _nonce: nonce,
              data: data_rc,
              rc4_hash__: rc4_hash_rc,
              signature: signature,
            }),
          });

          const result = JSON.parse(rc4.decode(response.data).replace("&&&START&&&", ""));

          if (result.code === 0) {
            this.log.info("Existing session is still valid");
            this.setState("info.connection", true, true);
            return true;
          } else {
            this.log.debug("Session test failed with code: " + result.code);
            return false;
          }
        } catch (error) {
          this.log.debug("Session test failed: " + error.message);
          return false;
        }
      }

      this.log.debug("No valid session found for resumption");
      return false;
    } catch (error) {
      this.log.warn("Error during session resumption: " + error.message);
      return false;
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

      const cookieData = JSON.parse(state.val);

      // Check if cookies are not too old (max 24 hours)
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      if (Date.now() - cookieData.timestamp > maxAge) {
        this.log.info("Saved cookies are too old, will perform fresh login");
        return false;
      }

      // Restore deviceId to maintain consistency
      if (cookieData.deviceId) {
        this.deviceId = cookieData.deviceId;
      }

      // Restore session data if available
      if (cookieData.session) {
        this.session = cookieData.session;
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
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
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
        // let type;
        if (command) {
          // type = command.split("-")[1];
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
            params = JSON.parse(state.val);
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
            const stateArray = state.val.replace(/ /g, "").split(",");
            command = stateArray[0];
            params = stateArray[1];
          }
          try {
            data = { id: 0, method: command, accessKey: "IOS00026747c5acafc2", params: JSON.parse(`[${params}]`) };
          } catch (error) {
            this.log.error(error);
          }
          this.log.debug(`Send remote plugin command ${JSON.stringify(data)} to ${deviceId}`);
        }
        if (id.includes(".remote.")) {
          url = "/miotspec/prop/set";
          data = {
            accessKey: "IOS00026747c5acafc2",
          };
          if (stateObject && stateObject.native.piid) {
            data.type = 3;
            data.params = [{ did: deviceId, siid: stateObject.native.siid, piid: stateObject.native.piid, value: state.val }];
          }
          if (stateObject && stateObject.native.aiid) {
            url = "/miotspec/action";
            data.params = { did: deviceId, siid: stateObject.native.siid, aiid: stateObject.native.aiid };
            if (typeof state.val !== "boolean") {
              try {
                data.params["in"] = JSON.parse(state.val);
              } catch (error) {
                this.log.error(error);
                return;
              }
            }

            // data.params.in = [];
          }
        }
        this.log.info(`Send: ${JSON.stringify(data)} to ${deviceId} via ${url}`);
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        await this.requestClient({
          method: "post",
          url: "https://" + this.config.region + "api.io.mi.com/app" + url,
          headers: this.header,
          data: qs.stringify({
            _nonce: nonce,
            data: data_rc,
            rc4_hash__: rc4_hash_rc,
            signature: signature,
          }),
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
            this.log.info(JSON.stringify(res.data));
            if (!res.data.result) {
              return;
            }
            const result = res.data.result;
            if (result.out) {
              const path = this.specActiosnToIdDict[result.did][result.siid + "-" + result.aiid];
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
                this.log.info(JSON.stringify(result.out));
              }
            }
          })
          .catch(async (error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        this.refreshTimeout = setTimeout(async () => {
          this.log.info("Update devices");
          await this.updateDevices();
          await this.updateDevicesViaSpec();
        }, 10 * 1000);
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
