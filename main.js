"use strict";

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const qs = require("qs");
const Json2iob = require("./lib/json2iob");
const RC4Crypt = require("./lib/rc4");
const crypto = require("crypto");
const tough = require("tough-cookie");
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
    this.region = "de";
    this.deviceId = this.randomString(40);
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

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");

    this.log.info("Login to MiHome Cloud");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
      await this.updateDevices();
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
    }
    this.refreshTokenInterval = setInterval(() => {
      this.refreshToken();
    }, 12 * 60 * 60 * 1000);
  }
  async login() {
    const firstStep = await this.requestClient({
      method: "get",
      url: "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true",
      headers: {
        Host: "account.xiaomi.com",
        Accept: "*/*",
        "User-Agent": "APP/com.xiaomi.mihome APPV/7.12.202 iosPassportSDK/4.2.14 iOS/14.8 miHSTS",
        "Accept-Language": "de-de",
        Cookie: "uLocale=de_DE; pass_ua=web",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.indexOf("&&&START&&&") === 0) {
          const data = res.data.replace("&&&START&&&", "");
          return JSON.parse(data);
        }
        return {};
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    if (!firstStep.sign) {
      this.log.error("No sign in first step");
      return;
    }
    await this.requestClient({
      method: "post",
      url: "https://account.xiaomi.com/pass/serviceLoginAuth2",
      headers: {
        Host: "account.xiaomi.com",
        Accept: "*/*",
        "User-Agent": "APP/com.xiaomi.mihome APPV/7.12.202 iosPassportSDK/4.2.14 iOS/14.8 miHSTS",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
        _json: "true",
        hash: crypto.createHash("md5").update(this.config.password).digest("hex").toUpperCase(),
        sid: "xiaomiio",
        callback: "https://sts.api.io.mi.com/sts",
        _sign: firstStep.sign,
        qs: "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
        user: this.config.username,
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.indexOf("&&&START&&&") === 0) {
          const data = res.data.replace("&&&START&&&", "");
          this.session = JSON.parse(data);
        }
        return {};
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!this.session.ok) {
      this.log.error("Login failed");
      return;
    }
    await this.requestClient({
      method: "get",
      url: this.session.location,
      headers: {
        Accept: "*/*",
        "User-Agent": "APP/com.xiaomi.mihome APPV/7.12.202 iosPassportSDK/4.2.14 iOS/14.8 miHSTS",
        "Accept-Language": "de-de",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.setState("info.connection", true, true);
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList() {
    const path = "/v2/home/device_list_page";
    const data = { get_split_device: true, support_smart_home: true, accessKey: "IOS00026747c5acafc2", limit: 300 };
    const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(path, data);
    await this.requestClient({
      method: "post",
      url: "https://" + this.region + ".api.io.mi.com/app" + path,
      headers: {
        "miot-encrypt-algorithm": "ENCRYPT-RC4",
        "content-type": "application/x-www-form-urlencoded",
        accept: "*/*",
        "accept-language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
        "operate-common":
          "_region=" +
          this.region +
          "&_language=" +
          this.region +
          "_deviceId=" +
          this.deviceId +
          "&_appVersion=7.12.202&_platform=1&_platformVersion=14.8",
        "user-agent": "iOS-14.8-7.12.202-iPhone10,5--" + this.deviceId + "-iPhone",
      },
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
        } catch (error) {
          this.log.error(error);
          return;
        }
        if (res.data.result !== 0) {
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
            const name = device.name;

            await this.setObjectNotExistsAsync(id, {
              type: "device",
              common: {
                name: name,
              },
              native: {},
            });
            await this.setObjectNotExistsAsync(id + ".remote", {
              type: "channel",
              common: {
                name: "Remote Controls",
              },
              native: {},
            });

            const remoteArray = [{ command: "Refresh", name: "True = Refresh" }];
            remoteArray.forEach((remote) => {
              this.setObjectNotExists(id + ".remote." + remote.command, {
                type: "state",
                common: {
                  name: remote.name || "",
                  type: remote.type || "boolean",
                  role: remote.role || "boolean",
                  def: remote.def || false,
                  write: true,
                  read: true,
                },
                native: {},
              });
            });
            this.json2iob.parse(id + ".general", device, { forceIndex: true });
          }
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
    let params = ["POST", path, `data=${data}`, signedNonce];
    const rc4 = new RC4Crypt(Buffer.from(signedNonce, "base64"), 1024);
    const rc4_hash = crypto.createHash("sha1").update(params.join("&"), "utf8").digest("base64");
    const data_rc = rc4.encode(data);
    const rc4_hash_rc = rc4.encode(rc4_hash);
    params = ["POST", path, `data=${data_rc}`, `rc4_hash__=${rc4_hash_rc}`, signedNonce];
    const signature = crypto.createHash("sha1").update(params.join("&"), "utf8").digest("base64");
    return { nonce, data_rc, rc4_hash_rc, signature, rc4 };
  }

  async updateDevices() {
    const statusArray = [
      {
        url: "/v2/device/batchgetdatas",
        path: "status",
        desc: "Status of the device",
        props: ["event.status"],
      },
    ];

    for (const element of statusArray) {
      for (const device of this.deviceArray) {
        const data = [{ did: device.did, props: element.props, accessKey: "IOS00026747c5acafc2" }];
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(element.url, data);
        await this.requestClient({
          method: "post",
          url: "https://" + this.region + ".api.io.mi.com/app" + element.url,
          headers: {
            "miot-encrypt-algorithm": "ENCRYPT-RC4",
            "content-type": "application/x-www-form-urlencoded",
            accept: "*/*",
            "accept-language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "operate-common":
              "_region=" +
              this.region +
              "&_language=" +
              this.region +
              "_deviceId=" +
              this.deviceId +
              "&_appVersion=7.12.202&_platform=1&_platformVersion=14.8",
            "user-agent": "iOS-14.8-7.12.202-iPhone10,5--" + this.deviceId + "-iPhone",
          },
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
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.result !== 0) {
              this.log.error("Error getting device statis");
              this.log.error(JSON.stringify(res.data));
              return;
            }
            this.log.debug(JSON.stringify(res.data));
            const forceIndex = true;
            const preferedArrayName = null;

            this.json2iob.parse(device.did + "." + element.path, data, {
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
            this.log.error(element.url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async refreshToken() {
    this.log.debug("Refresh token");
    await this.login();
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
        let command = id.split(".")[4];
        const type = command.split("-")[1];
        command = command.split("-")[0];

        if (id.split(".")[4] === "Refresh") {
          this.updateDevices();
          return;
        }
        const url = "/v2/device/batchgetdatas";
        const data = [{ did: deviceId, props: ["event.status"], accessKey: "IOS00026747c5acafc2" }];
        const { nonce, data_rc, rc4_hash_rc, signature, rc4 } = this.createBody(url, data);
        await this.requestClient({
          method: "post",
          url: "https://" + this.region + ".api.io.mi.com/app" + url,
          headers: {
            "miot-encrypt-algorithm": "ENCRYPT-RC4",
            "content-type": "application/x-www-form-urlencoded",
            accept: "*/*",
            "accept-language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "operate-common":
              "_region=" +
              this.region +
              "&_language=" +
              this.region +
              "_deviceId=" +
              this.deviceId +
              "&_appVersion=7.12.202&_platform=1&_platformVersion=14.8",
            "user-agent": "iOS-14.8-7.12.202-iPhone10,5--" + this.deviceId + "-iPhone",
          },
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
            } catch (error) {
              this.log.error(error);
              return;
            }
            if (res.data.result !== 0) {
              this.log.error("Error getting device statis");
              this.log.error(JSON.stringify(res.data));
              return;
            }
            this.log.debug(JSON.stringify(res.data));
          })
          .catch(async (error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        this.refreshTimeout = setTimeout(async () => {
          this.log.info("Update devices");
          await this.updateDevices();
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
