const configDes = [
  {
    props: [{ supportType: [1] }],
    cards: { layout_type: 0, card_items: [{ cardType: 6 }] },
    models: [
      "mijia.camera.v1",
      "mijia.camera.v3",
      "chuangmi.camera.xiaobai",
      "chuangmi.camera.v2",
      "isa.camera.isc5c1",
      "isa.camera.isc5",
      "isa.camera.hl5",
      "isa.camera.iscac1",
      "chuangmi.camera.v5",
      "chuangmi.camera.v6",
      "chuangmi.camera.v3",
      "chuangmi.camera.v4",
      "isa.camera.df3",
      "lumi.camera.aq1",
      "yunyi.camera.v1",
      "yunyi.camera.mj1",
      "mijia.camera.v4",
      "chuangmi.camera.ipc009",
      "chuangmi.camera.ipc010",
      "chuangmi.camera.ipc007b",
      "chuangmi.camera.ipc004b",
      "chuangmi.camera.ipc013",
      "chuangmi.camera.ipc013b",
      "chuangmi.camera.ipc013d",
      "chuangmi.camera.ipc016",
      "chuangmi.camera.ipc16a2",
      "chuangmi.camera.ipc13a2",
      "chuangmi.camera.ipc017",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.st_temp_dec",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "温度", en: "Temperature" },
        ratio: 0.1,
        format: "%.0f",
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        prop_name: { zh_CN: "挡位选择", en: "Mode" },
        prop_extra: [
          { value: "cooling", desc: { zh_CN: "制冷", en: "Cool" } },
          { value: "arefaction", desc: { zh_CN: "除湿", en: "Dry" } },
          { value: "wind", desc: { zh_CN: "送风", en: "Wind" } },
          { value: "heat", desc: { zh_CN: "制热", en: "Heat" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 3,
          operation: [
            {
              param: ["cooling"],
              method: "set_mode",
              prop_value: "cooling",
              button_name: { zh_CN: "制冷", en: "Cool" },
              button_image: {
                selected: "popup_icon_cold_hig",
                unable: "popup_icon_cold_unable",
                normal: "popup_icon_cold_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["heat"],
              method: "set_mode",
              prop_value: "heat",
              button_name: { zh_CN: "制热", en: "Heat" },
              button_image: {
                selected: "popup_icon_sun_hig",
                unable: "popup_icon_sun_unable",
                normal: "popup_icon_sun_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["wind"],
              method: "set_mode",
              prop_value: "wind",
              button_name: { zh_CN: "送风", en: "Wind" },
              button_image: {
                selected: "popup_icon_wind_hig",
                unable: "popup_icon_wind_disable",
                normal: "popup_icon_wind_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
        {
          prop_key: "prop.st_temp_dec",
          cardType: 4,
          operation: [
            {
              method: "set_temperature",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.comfort", value: "on" },
              ],
            },
          ],
          param_range: { min: 160, max: 320 },
          param_delta: 10,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "int" }],
        },
      ],
    },
    models: [
      "zhimi.aircondition.v1",
      "zhimi.aircondition.v2",
      "zhimi.aircondition.sa1",
      "zhimi.aircondition.ma1",
      "zhimi.aircondition.ma2",
      "zhimi.aircondition.ma3",
      "zhimi.aircondition.ma4",
      "zhimi.aircondition.za1",
      "zhimi.aircondition.za2",
      "zhimi.aircondition.va1",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
      ],
    },
    models: [
      "chuangmi.plug.m1",
      "chuangmi.plug.m2",
      "zimi.powerstrip.v2",
      "zimi.powerstrip.v1",
      "qmi.powerstrip.v1",
      "qmi.powerstrip.v2",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.channel_0",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["channel_0", "on"],
              method: "toggle_plug",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["channel_0", "off"],
              method: "toggle_plug",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
            },
          ],
          prop_key: "prop.channel_0",
        },
      ],
    },
    models: ["lumi.ctrl_86plug.v1", "lumi.plug.saus01", "lumi.plug.mitw01"],
  },
  {
    props: [
      {
        prop_key: "prop.current_status",
        supportType: [1],
        switchStatus: ["run"],
        prop_name: { en: "Switch", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "run", desc: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
          { value: "pause", desc: { en: "Pause", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Mode", zh_HK: "音量調節", zh_CN: "音量调节", zh_TW: "音量調節" },
        prop_key: "prop.current_volume",
      },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: [],
              method: "pause",
              prop_value: "run",
              button_name: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "btn_radio_play",
              },
            },
            {
              param: [],
              method: "resume",
              prop_value: "pause",
              button_name: { en: "Paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.current_status",
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_volume", disable_status: [{ key: "prop.current_status", value: "pause" }] }],
          prop_key: "prop.current_volume",
          param_type: [{ type: "JSONObject", key: "volume" }, { type: "int" }],
          small_image: "seekbar_thumb_sound",
          param_range: { min: 1, max: 31 },
        },
      ],
    },
    models: ["chuangmi.radio.v1", "chuangmi.radio.v2"],
  },
  {
    props: [
      {
        supportType: [1],
        subProps: [
          {
            prop_key: "state",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "state", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "當前狀態", zh_CN: "当前状态", zh_TW: "當前狀態" },
            prop_extra: [
              { value: 2, desc: { en: "Dormant", zh_HK: "休眠", zh_CN: "休眠", zh_TW: "休眠" } },
              {
                value: 3,
                desc: { en: "Wait instruction", zh_HK: "等待指令", zh_CN: "等待指令", zh_TW: "等待指令" },
              },
              { value: 5, desc: { en: "Sweeping", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" } },
              { value: 6, desc: { en: "Return charging", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" } },
              {
                value: 7,
                desc: { en: "Remote control", zh_HK: "遙控中", zh_CN: "遥控中", zh_TW: "遙控中" },
              },
              {
                value: 8,
                desc: { en: "Charging in progress", zh_HK: "充電中", zh_CN: "充电中", zh_TW: "充電中" },
              },
              {
                value: 9,
                desc: { en: "Charging error", zh_HK: "充電報錯", zh_CN: "充电报错", zh_TW: "充電報錯" },
              },
              { value: 10, desc: { en: "Pause", zh_HK: "暫停", zh_CN: "暂停", zh_TW: "暫停" } },
              {
                value: 11,
                desc: { en: "Partial sweeping", zh_HK: "局部清掃", zh_CN: "局部清扫", zh_TW: "局部清掃" },
              },
              { value: 12, desc: { en: "Error", zh_HK: "報錯", zh_CN: "报错", zh_TW: "報錯" } },
              { value: 13, desc: { en: "Upgrading", zh_HK: "升級中", zh_CN: "升级中", zh_TW: "升級中" } },
              { value: 14, desc: { en: "Upgrading", zh_HK: "升級中", zh_CN: "升级中", zh_TW: "升級中" } },
            ],
          },
          {
            prop_key: "fan_power",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "fan_power", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "狀態", zh_CN: "状态", zh_TW: "狀態" },
          },
        ],
        prop_key: "event.status",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        { prop_key: "event.status", sub_prop_key: "state", cardType: 14 },
        {
          supportGrid: 1,
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 5,
              button_name: { en: "Pause", zh_HK: "清掃中", zh_CN: "清扫中", zh_TW: "清掃中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_clean_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
                { key: "state", value: 12 },
              ],
            },
            {
              param: [],
              method: "app_start",
              prop_value: 10,
              button_name: { en: "Start clean", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" },
              button_image: {
                selected: "popup_icon_clean_hig",
                unable: "popup_icon_clean_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 4 },
                { key: "state", value: 6 },
                { key: "state", value: 7 },
                { key: "state", value: 9 },
                { key: "state", value: 11 },
                { key: "state", value: 12 },
                { key: "state", value: 13 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
        {
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 6,
              button_name: { en: "Pause", zh_HK: "回充中", zh_CN: "回充中", zh_TW: "回充中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_stow_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
                { key: "state", value: 12 },
              ],
            },
            {
              param: [],
              method: "app_charge",
              prop_value: 10,
              button_name: { en: "Charge", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" },
              button_image: {
                selected: "popup_icon_stow_hig",
                unable: "popup_icon_stow_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 4 },
                { key: "state", value: 5 },
                { key: "state", value: 7 },
                { key: "state", value: 8 },
                { key: "state", value: 9 },
                { key: "state", value: 11 },
                { key: "state", value: 12 },
                { key: "state", value: 13 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
      ],
    },
    models: ["rockrobo.vacuum.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_extra: [
          { desc: { en: "Close", zh_HK: "關閉", zh_CN: "关闭", zh_TW: "關閉" }, value: "on" },
          { desc: { en: "Open", zh_HK: "打開", zh_CN: "打开", zh_TW: "打開" }, value: "off" },
        ],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
      {
        supportType: [1],
        prop_key: "prop.bright",
        prop_name: { en: "Set bright", zh_HK: "亮度調節", zh_CN: "亮度调节", zh_TW: "亮度調節" },
      },
      {
        supportType: [1],
        prop_key: "prop.ct",
        prop_name: { en: "Set ct", zh_HK: "色温調節", zh_CN: "色温调节", zh_TW: "色温調節" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 13,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          prop_key: "prop.bright",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "seekbar_thumb_light",
          param_range: { min: 1, max: 100 },
        },
        {
          prop_key: "prop.ct",
          cardType: 16,
          operation: [
            {
              param: ["smooth", 500],
              method: "set_ct_abx",
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          param_range: { min: 1700, max: 6500 },
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["yeelink.light.bslamp1", "yeelink.light.bslamp2"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_extra: [
          { desc: { en: "Close", zh_HK: "關閉", zh_CN: "关闭", zh_TW: "關閉" }, value: "on" },
          { desc: { en: "Open", zh_HK: "打開", zh_CN: "打开", zh_TW: "打開" }, value: "off" },
        ],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
      {
        supportType: [1],
        prop_key: "prop.bright",
        prop_name: { en: "Set bright", zh_HK: "亮度調節", zh_CN: "亮度调节", zh_TW: "亮度調節" },
      },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          prop_key: "prop.bright",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "seekbar_thumb_light",
          param_range: { min: 1, max: 100 },
        },
      ],
    },
    models: [
      "yeelink.light.color1",
      "yeelink.light.color2",
      "yeelink.light.color3",
      "yeelink.light.lamp1",
      "yeelink.light.lamp2",
      "yeelink.light.mono1",
      "yeelink.light.strip1",
      "yeelink.light.strip2",
      "yeelink.light.ct2",
      "yeelink.light.lamp3",
      "yeelink.light.lamp5",
      "yilai.light.ceiling1",
      "yilai.light.ceiling2",
      "yilai.light.ceiling3",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.temp",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "温度", en: "temp" },
        prop_extra: [
          { desc: { zh_CN: "低温", en: "Lower" }, param_range: { min: 16, max: 20 } },
          { desc: { zh_CN: "室温", en: "Normal" }, param_range: { min: 20, max: 26 } },
          { desc: { zh_CN: "高温", en: "High" }, param_range: { min: 26, max: 31 } },
        ],
        format: "%.1f",
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        prop_name: { zh_CN: "挡位选择", en: "Mode" },
        prop_extra: [
          { value: "auto", desc: { zh_CN: "自动", en: "Auto" } },
          { value: "cold", desc: { zh_CN: "制冷", en: "Cool" } },
          { value: "dehumidifier", desc: { zh_CN: "除湿", en: "Dry" } },
          { value: "wind", desc: { zh_CN: "送风", en: "Wind" } },
          { value: "hot", desc: { zh_CN: "制热", en: "Heat" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { zh_CN: "自动", en: "Auto" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["cold"],
              method: "set_mode",
              prop_value: "cold",
              button_name: { zh_CN: "制冷", en: "Cool" },
              button_image: {
                selected: "popup_icon_cold_hig",
                unable: "popup_icon_cold_unable",
                normal: "popup_icon_cold_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["hot"],
              method: "set_mode",
              prop_value: "hot",
              button_name: { zh_CN: "制热", en: "Heat" },
              button_image: {
                selected: "popup_icon_sun_hig",
                unable: "popup_icon_sun_unable",
                normal: "popup_icon_sun_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
        {
          prop_key: "prop.temp",
          cardType: 4,
          operation: [
            {
              method: "set_temp",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.mode", value: "auto" },
              ],
            },
          ],
          param_range: { min: 17, max: 30 },
          param_delta: 0.5,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "double" }],
        },
      ],
    },
    models: ["midea.aircondition.v1", "midea.aircondition.xa1", "midea.aircondition.xa2"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.temp",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "温度", en: "temp" },
        prop_extra: [
          { desc: { zh_CN: "低温", en: "Lower" }, param_range: { min: 16, max: 20 } },
          { desc: { zh_CN: "室温", en: "Normal" }, param_range: { min: 20, max: 26 } },
          { desc: { zh_CN: "高温", en: "High" }, param_range: { min: 26, max: 31 } },
        ],
        format: "%.1f",
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        prop_name: { zh_CN: "挡位选择", en: "Mode" },
        prop_extra: [
          { value: "auto", desc: { zh_CN: "自动", en: "Auto" } },
          { value: "cold", desc: { zh_CN: "制冷", en: "Cool" } },
          { value: "dehumidifier", desc: { zh_CN: "除湿", en: "Dry" } },
          { value: "wind", desc: { zh_CN: "送风", en: "Wind" } },
          { value: "hot", desc: { zh_CN: "制热", en: "Heat" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { zh_CN: "自动", en: "Auto" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["cold"],
              method: "set_mode",
              prop_value: "cold",
              button_name: { zh_CN: "制冷", en: "Cool" },
              button_image: {
                selected: "popup_icon_cold_hig",
                unable: "popup_icon_cold_unable",
                normal: "popup_icon_cold_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["hot"],
              method: "set_mode",
              prop_value: "hot",
              button_name: { zh_CN: "制热", en: "Heat" },
              button_image: {
                selected: "popup_icon_sun_hig",
                unable: "popup_icon_sun_unable",
                normal: "popup_icon_sun_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
        {
          prop_key: "prop.temp",
          cardType: 4,
          operation: [
            {
              method: "set_temp",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.mode", value: "auto" },
              ],
            },
          ],
          param_range: { min: 16, max: 32 },
          param_delta: 0.5,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "double" }],
        },
      ],
    },
    models: ["aux.aircondition.v1", "aux.aircondition.hc1"],
  },
  {
    props: [
      {
        prop_key: "prop.channel_0",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Left Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.channel_1",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Right Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        {
          cardType: 1,
          operation: [
            {
              param: ["neutral_0", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_name: { en: "Left Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_0", "off"],
              method: "toggle_ctrl_neutral",
              prop_value: "on",
              button_name: { en: "Left Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
            },
          ],
          prop_key: "prop.channel_0",
        },
        {
          cardType: 1,
          operation: [
            {
              param: ["neutral_1", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_name: { en: "Right Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_1", "off"],
              method: "toggle_ctrl_neutral",
              prop_value: "on",
              button_name: { en: "Right Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
            },
          ],
          prop_key: "prop.channel_1",
        },
      ],
    },
    models: ["lumi.ctrl_ln2.v1", "lumi.switch.b2naus01", "lumi.ctrl_ln2.aq1"],
  },
  {
    props: [
      {
        prop_key: "prop.tds_out",
        prop_unit: "mg/L",
        supportType: [1],
        prop_name: { en: "TDS", zh_HK: "TDS", zh_CN: "TDS", zh_TW: "TDS" },
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 80 } },
          { text_color: "#FFE0AC15", param_range: { min: 81, max: 500 } },
        ],
      },
    ],
    cards: {
      supportGrid: 1,
      layout_type: 0,
      card_items: [{ supportGrid: 1, cardType: 7, prop_key: "prop.tds_out" }],
    },
    models: ["yunmi.waterpuri.lx5"],
  },
  {
    props: [
      { prop_key: "prop.RCSet" },
      { prop_key: "prop.CCSet" },
      { prop_key: "prop.RCSetTemp", format: "%.0f", prop_name: { zh_CN: "冷藏室", en: "RCTemp" } },
      { prop_key: "prop.CCSetTemp", format: "%.0f", prop_name: { zh_CN: "变温室", en: "CCTemp" } },
      { prop_key: "prop.FCSetTemp", format: "%.0f", prop_name: { zh_CN: "冷冻室", en: "FCTemp" } },
    ],
    cards: {
      layout_type: 5,
      card_items: [
        {
          prop_key: "prop.RCSetTemp",
          cardType: 4,
          operation: [{ method: "setRCSetTemp", disable_status: [{ key: "prop.RCSet", value: "off" }] }],
          param_range: { min: 2, max: 8 },
          param_delta: 1,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
        {
          prop_key: "prop.CCSetTemp",
          cardType: 4,
          operation: [{ method: "setCCSetTemp", disable_status: [{ key: "prop.CCSet", value: "off" }] }],
          param_range: { min: -18, max: 8 },
          param_delta: 1,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
        {
          prop_key: "prop.FCSetTemp",
          cardType: 4,
          operation: [{ method: "setFCSetTemp" }],
          param_range: { min: -25, max: -15 },
          param_delta: 1,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["viomi.fridge.w1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "开关", en: "power" },
      },
      { supportType: [1], prop_name: { zh_CN: "亮度调节", en: "Set bright" }, prop_key: "prop.bright" },
      { supportType: [1], prop_name: { zh_CN: "色温调节", en: "Set cct" }, prop_key: "prop.cct" },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          prop_key: "prop.cct",
          cardType: 11,
          operation: [{ method: "set_cct" }],
          param_range: { min: 1, max: 100 },
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
        {
          prop_key: "prop.bright",
          cardType: 5,
          operation: [{ method: "set_bright" }],
          param_range: { min: 1, max: 100 },
          small_image: "seekbar_thumb_light",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: [
      "philips.light.ceiling",
      "philips.light.zyceiling",
      "philips.light.candle",
      "philips.light.candle2",
      "philips.light.downlight",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "开关", en: "power" },
      },
      { supportType: [1], prop_name: { zh_CN: "亮度调节", en: "Set bright" }, prop_key: "prop.bright" },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          prop_key: "prop.bright",
          cardType: 5,
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          param_range: { min: 1, max: 100 },
          small_image: "seekbar_thumb_light",
          param_type: [{ type: "JSONArray", int: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["philips.light.zysread", "philips.light.moonlight"],
  },
  {
    props: [
      {
        prop_key: "prop.onoff_state",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.onoff_state",
        },
      ],
    },
    models: ["lumi.acpartner.v1", "lumi.acpartner.v2", "lumi.acpartner.v3"],
  },
  {
    props: [
      {
        prop_key: "prop.aqi",
        prop_unit: "μg/m³",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        switchStatus: ["auto", "strong", "silent"],
        prop_name: { en: "Switch", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["idle"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "idle",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
            {
              param: ["idle"],
              method: "set_mode",
              prop_value: "strong",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
            {
              param: ["idle"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.mode",
        },
        { cardType: 17, prop_key: "prop.aqi" },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Automatic", zh_HK: "自動", zh_CN: "自动", zh_TW: "自動" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.mode", value: "idle" }],
            },
            {
              param: ["strong"],
              method: "set_mode",
              prop_value: "strong",
              button_name: { en: "High-speed", zh_HK: "高速", zh_CN: "高速", zh_TW: "高速" },
              button_image: {
                selected: "btn_highspeed_on",
                unable: "btn_highspeed_unable",
                normal: "btn_highspeed_off",
              },
              disable_status: [{ key: "prop.mode", value: "idle" }],
            },
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Sleep", zh_HK: "睡眠", zh_CN: "睡眠", zh_TW: "睡眠" },
              button_image: { selected: "btn_sleep_on", unable: "btn_sleep_unable", normal: "btn_sleep_off" },
              disable_status: [{ key: "prop.mode", value: "idle" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["zhimi.airpurifier.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.aqi",
        prop_unit: "μg/m³",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        supportType: [1],
        prop_key: "prop.mode",
        prop_name: { en: "Mode", zh_HK: "模式", zh_CN: "模式", zh_TW: "模式" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 17, prop_key: "prop.aqi" },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Automatic", zh_HK: "自動", zh_CN: "自动", zh_TW: "自動" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["strong"],
              method: "set_mode",
              prop_value: "strong",
              button_name: { en: "High speed", zh_HK: "高速", zh_CN: "高速", zh_TW: "高速" },
              button_image: {
                selected: "btn_highspeed_on",
                unable: "btn_highspeed_unable",
                normal: "btn_highspeed_off",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Sleep", zh_HK: "睡眠", zh_CN: "睡眠", zh_TW: "睡眠" },
              button_image: { selected: "btn_sleep_on", unable: "btn_sleep_unable", normal: "btn_sleep_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["zhimi.airpurifier.v3"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.aqi",
        prop_unit: "μg/m³",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        supportType: [1],
        prop_key: "prop.mode",
        prop_name: { en: "Mode", zh_HK: "模式", zh_CN: "模式", zh_TW: "模式" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 17, prop_key: "prop.aqi" },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Automatic", zh_HK: "自動", zh_CN: "自动", zh_TW: "自動" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Sleep", zh_HK: "睡眠", zh_CN: "睡眠", zh_TW: "睡眠" },
              button_image: { selected: "btn_sleep_on", unable: "btn_sleep_unable", normal: "btn_sleep_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["favorite"],
              method: "set_mode",
              prop_value: "favorite",
              button_name: { en: "Favorite", zh_HK: "最愛", zh_CN: "最爱", zh_TW: "最愛" },
              button_image: {
                selected: "popup_icon_love_hig",
                unable: "popup_icon_love_unable",
                normal: "popup_icon_love_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: [
      "zhimi.airpurifier.m1",
      "zhimi.airpurifier.m2",
      "zhimi.airpurifier.v6",
      "zhimi.airpurifier.sa2",
      "zhimi.airpurifier.ma2",
      "zhimi.airpurifier.mb1",
      "zhimi.airpurifier.mc1",
      "zhimi.airpurifier.v7",
      "zhimi.airpurifier.ma3",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.aqi",
        prop_unit: "μg/m³",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        supportType: [1],
        prop_key: "prop.mode",
        prop_name: { en: "Mode", zh_HK: "模式", zh_CN: "模式", zh_TW: "模式" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 17, prop_key: "prop.aqi" },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Automatic", zh_HK: "自動", zh_CN: "自动", zh_TW: "自動" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Sleep", zh_HK: "睡眠", zh_CN: "睡眠", zh_TW: "睡眠" },
              button_image: { selected: "btn_sleep_on", unable: "btn_sleep_unable", normal: "btn_sleep_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["favorite"],
              method: "set_mode",
              prop_value: "favorite",
              button_name: { en: "Favorite", zh_HK: "最愛", zh_CN: "最爱", zh_TW: "最愛" },
              button_image: {
                selected: "popup_icon_love_hig",
                unable: "popup_icon_love_unable",
                normal: "popup_icon_love_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: [
      "zhimi.airpurifier.m1",
      "zhimi.airpurifier.m2",
      "zhimi.airpurifier.v6",
      "zhimi.airpurifier.sa2",
      "zhimi.airpurifier.ma2",
      "zhimi.airpurifier.mb1",
      "zhimi.airpurifier.mc1",
      "zhimi.airpurifier.v7",
      "zhimi.airpurifier.ma3",
      "zhimi.airpurifier.sb1",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.temperature",
        prop_unit: "℃",
        supportType: [1, 2, 3],
        prop_name: { en: "TEMP", zh_HK: "溫度", zh_CN: "温度", zh_TW: "溫度" },
        ratio: 0.01,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 40 } },
        ],
      },
      {
        prop_key: "prop.humidity",
        prop_unit: "%",
        supportType: [1, 2, 3],
        prop_name: { en: "Humidity", zh_HK: "濕度", zh_CN: "湿度", zh_TW: "濕度" },
        ratio: 0.01,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.temperature" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.humidity" },
      ],
    },
    models: ["lumi.sensor_ht.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.temperature",
        prop_unit: "℃",
        supportType: [1, 2, 3],
        prop_name: { en: "TEMP", zh_HK: "溫度", zh_CN: "温度", zh_TW: "溫度" },
        ratio: 0.01,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 40 } },
        ],
      },
      {
        prop_key: "prop.humidity",
        prop_unit: "%",
        supportType: [1, 2, 3],
        prop_name: { en: "Humidity", zh_HK: "濕度", zh_CN: "湿度", zh_TW: "濕度" },
        ratio: 0.01,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
      {
        prop_key: "prop.pressure",
        prop_unit: "Kpa",
        supportType: [1, 2],
        prop_name: { en: "ATM", zh_HK: "氣壓", zh_CN: "气压", zh_TW: "氣壓" },
        ratio: 0.001,
        format: "%.0f",
      },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.temperature" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.humidity" },
        { cardType: 7, prop_key: "prop.pressure" },
      ],
    },
    models: ["lumi.weather.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.humidity",
        prop_unit: "%",
        supportType: [1, 2],
        prop_name: { en: "Humidity", zh_HK: "濕度", zh_CN: "湿度", zh_TW: "濕度" },
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
      {
        supportType: [1],
        prop_key: "prop.mode",
        prop_name: { en: "Gears", zh_HK: "檔位", zh_CN: "档位", zh_TW: "檔位" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 7, prop_key: "prop.humidity" },
        {
          cardType: 12,
          operation: [
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "One", zh_HK: "1擋", zh_CN: "1挡", zh_TW: "1擋" },
              button_image: {
                selected: "popup_icon_one_hig",
                unable: "popup_icon_one_unable",
                normal: "popup_icon_one_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["medium"],
              method: "set_mode",
              prop_value: "medium",
              button_name: { en: "Two", zh_HK: "2擋", zh_CN: "2挡", zh_TW: "2擋" },
              button_image: {
                selected: "popup_icon_two_hig",
                unable: "popup_icon_two_unable",
                normal: "popup_icon_two_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["high"],
              method: "set_mode",
              prop_value: "high",
              button_name: { en: "Three", zh_HK: "3擋", zh_CN: "3挡", zh_TW: "3擋" },
              button_image: {
                selected: "popup_icon_three_hig",
                unable: "popup_icon_three_unable",
                normal: "popup_icon_three_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["zhimi.humidifier.v1", "zhimi.humidifier.ca1", "zhimi.humidifier.ca2"],
  },
  {
    props: [
      {
        prop_key: "prop.aqi",
        supportType: [1, 2, 3],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 7, prop_key: "prop.aqi" }] },
    models: ["zhimi.airmonitor.v1"],
  },
  {
    props: [
      { prop_key: "prop.RCSet" },
      { prop_key: "prop.RCSetTemp", format: "%.0f", prop_name: { zh_CN: "冷藏室", en: "RCTemp" } },
      { prop_key: "prop.FCSetTemp", format: "%.0f", prop_name: { zh_CN: "冷冻室", en: "FCTemp" } },
    ],
    cards: {
      layout_type: 5,
      card_items: [
        {
          prop_key: "prop.RCSetTemp",
          cardType: 4,
          operation: [{ method: "setRCSetTemp", disable_status: [{ key: "prop.RCSet", value: "off" }] }],
          param_range: { min: 2, max: 8 },
          param_delta: 1,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
        {
          prop_key: "prop.FCSetTemp",
          cardType: 4,
          operation: [{ method: "setFCSetTemp" }],
          param_range: { min: -25, max: -15 },
          param_delta: 1,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["viomi.fridge.w2"],
  },
  {
    props: [
      {
        prop_key: "prop.setup_tempe",
        prop_unit: "℃",
        supportType: [1, 2],
        prop_name: { zh_CN: "出水温度", en: "WaterTemp" },
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 100 } },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 7, prop_key: "prop.setup_tempe" }] },
    models: ["yunmi.plmachine.mg3"],
  },
  {
    props: [
      {
        prop_key: "event.alarm",
        supportType: [1, 2],
        prop_value_type: [{ key: "value", type: "JSONObject" }, { index: 0, type: "JSONArray" }, { type: "int" }],
        prop_name: { en: "Status", zh_HK: "燃氣", zh_CN: "燃气", zh_TW: "燃氣" },
        prop_extra: [
          {
            value: 0,
            text_color: "#2DD1E2",
            desc: { en: "Security", zh_HK: "安全", zh_CN: "安全", zh_TW: "安全" },
          },
          {
            value: 1,
            text_color: "#F43F31",
            desc: { en: "warning", zh_HK: "報警", zh_CN: "报警", zh_TW: "報警" },
          },
          {
            value: 2,
            text_color: "#F43F31",
            desc: { en: "Analog warning", zh_HK: "模擬報警", zh_CN: "模拟报警", zh_TW: "模擬報警" },
          },
          {
            value: 8,
            text_color: "#F43F31",
            desc: { en: "Battery failure alarm", zh_HK: "電池故障", zh_CN: "电池故障", zh_TW: "電池故障" },
          },
          {
            value: 64,
            text_color: "#F43F31",
            desc: {
              en: "Sensitivity fault alarm",
              zh_HK: "靈敏度故障",
              zh_CN: "灵敏度故障",
              zh_TW: "靈敏度故障",
            },
          },
          {
            value: 32768,
            text_color: "#F43F31",
            desc: {
              en: "IIC communication failure",
              zh_HK: "IIC通信故障",
              zh_CN: "IIC通信故障",
              zh_TW: "IIC通信故障",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "event.alarm" }] },
    models: ["lumi.sensor_natgas.v1"],
  },
  {
    props: [
      {
        prop_key: "event.alarm",
        supportType: [1, 2],
        prop_value_type: [{ key: "value", type: "JSONObject" }, { index: 0, type: "JSONArray" }, { type: "int" }],
        prop_name: { en: "Status", zh_HK: "煙霧", zh_CN: "烟雾", zh_TW: "煙霧" },
        prop_extra: [
          {
            value: 0,
            text_color: "#2DD1E2",
            desc: { en: "Security", zh_HK: "安全", zh_CN: "安全", zh_TW: "安全" },
          },
          {
            value: 1,
            text_color: "#F43F31",
            desc: { en: "Warning", zh_HK: "報警", zh_CN: "报警", zh_TW: "報警" },
          },
          {
            value: 2,
            text_color: "#F43F31",
            desc: { en: "Analog warning", zh_HK: "模擬報警", zh_CN: "模拟报警", zh_TW: "模擬報警" },
          },
          {
            value: 8,
            text_color: "#F43F31",
            desc: { en: "Battery failure alarm", zh_HK: "電池故障", zh_CN: "电池故障", zh_TW: "電池故障" },
          },
          {
            value: 64,
            text_color: "#F43F31",
            desc: {
              en: "Sensitivity fault alarm",
              zh_HK: "靈敏度故障",
              zh_CN: "灵敏度故障",
              zh_TW: "靈敏度故障",
            },
          },
          {
            value: 32768,
            text_color: "#F43F31",
            desc: {
              en: "IIC communication failure",
              zh_HK: "IIC通信故障",
              zh_CN: "IIC通信故障",
              zh_TW: "IIC通信故障",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "event.alarm" }] },
    models: ["lumi.sensor_smoke.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.leak",
        supportType: [1, 2],
        prop_name: { en: "Status", zh_HK: "水浸", zh_CN: "水浸", zh_TW: "水浸" },
        prop_extra: [
          {
            value: "1",
            text_color: "#F43F31",
            desc: { en: "On", zh_HK: "水浸", zh_CN: "水浸", zh_TW: "水浸" },
          },
          {
            value: "0",
            text_color: "#2DD1E2",
            desc: { en: "Off", zh_HK: "安全", zh_CN: "安全", zh_TW: "安全" },
          },
          {
            value: "null",
            text_color: "#2DD1E2",
            desc: { en: "Off", zh_HK: "安全", zh_CN: "安全", zh_TW: "安全" },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.leak" }] },
    models: ["lumi.sensor_wleak.aq1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Gear", zh_HK: "檔位", zh_CN: "档位", zh_TW: "檔位" },
        prop_key: "prop.speed_level",
      },
      {
        prop_key: "prop.angle_enable",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Turn", zh_HK: "轉動", zh_CN: "转动", zh_TW: "轉動" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 1,
          operation: [
            {
              param: [60],
              method: "set_angle",
              prop_value: "off",
              button_name: { en: "Turn", zh_HK: "轉動", zh_CN: "转动", zh_TW: "轉動" },
              button_image: {
                selected: "btn_rotating_off",
                unable: "btn_rotating_unable",
                normal: "btn_rotating",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["off"],
              method: "set_angle_enable",
              prop_value: "on",
              disable_status: [{ key: "prop.power", value: "off" }],
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.angle_enable",
        },
        {
          prop_key: "prop.speed_level",
          cardType: 12,
          operation: [
            {
              param: [25],
              method: "set_speed_level",
              prop_value: 25,
              button_name: { en: "One", zh_HK: "1擋", zh_CN: "1挡", zh_TW: "1擋" },
              button_image: {
                selected: "popup_icon_one_hig",
                unable: "popup_icon_one_unable",
                normal: "popup_icon_one_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [50],
              method: "set_speed_level",
              prop_value: 50,
              button_name: { en: "Two", zh_HK: "2擋", zh_CN: "2挡", zh_TW: "2擋" },
              button_image: {
                selected: "popup_icon_two_hig",
                unable: "popup_icon_two_unable",
                normal: "popup_icon_two_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [75],
              method: "set_speed_level",
              prop_value: 75,
              button_name: { en: "Three", zh_HK: "3擋", zh_CN: "3挡", zh_TW: "3擋" },
              button_image: {
                selected: "popup_icon_three_hig",
                unable: "popup_icon_three_unable",
                normal: "popup_icon_three_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [100],
              method: "set_speed_level",
              prop_value: 100,
              button_name: { en: "Four", zh_HK: "4擋", zh_CN: "4挡", zh_TW: "4擋" },
              button_image: {
                selected: "popup_icon_four_hig",
                unable: "popup_icon_four_unable",
                normal: "popup_icon_four_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          param_range: { min: 25, max: 100 },
          param_delta: 25,
        },
      ],
    },
    models: ["zhimi.fan.v2"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Gear", zh_HK: "擋位", zh_CN: "挡位", zh_TW: "擋位" },
        prop_key: "prop.fan_level",
      },
      {
        prop_key: "prop.angle_enable",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Turn", zh_HK: "轉動", zh_CN: "转动", zh_TW: "轉動" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 1,
          operation: [
            {
              param: [60],
              method: "set_angle",
              prop_value: "off",
              button_name: { en: "Turn", zh_HK: "轉動", zh_CN: "转动", zh_TW: "轉動" },
              button_image: {
                selected: "btn_rotating_off",
                unable: "btn_rotating_unable",
                normal: "btn_rotating",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["off"],
              method: "set_angle_enable",
              prop_value: "on",
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.angle_enable",
        },
        {
          prop_key: "prop.fan_level",
          cardType: 12,
          operation: [
            {
              param: [1],
              method: "set_fan_level",
              prop_value: 1,
              button_name: { en: "One", zh_HK: "一擋", zh_CN: "1挡", zh_TW: "一擋" },
              button_image: {
                selected: "popup_icon_one_hig",
                unable: "popup_icon_one_unable",
                normal: "popup_icon_one_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [2],
              method: "set_fan_level",
              prop_value: 2,
              button_name: { en: "Two", zh_HK: "二擋", zh_CN: "2挡", zh_TW: "二擋" },
              button_image: {
                selected: "popup_icon_two_hig",
                unable: "popup_icon_two_unable",
                normal: "popup_icon_two_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [3],
              method: "set_fan_level",
              prop_value: 3,
              button_name: { en: "Three", zh_HK: "三擋", zh_CN: "3挡", zh_TW: "三擋" },
              button_image: {
                selected: "popup_icon_three_hig",
                unable: "popup_icon_three_unable",
                normal: "popup_icon_three_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: [4],
              method: "set_fan_level",
              prop_value: 4,
              button_name: { en: "Four", zh_HK: "四擋", zh_CN: "4挡", zh_TW: "四擋" },
              button_image: {
                selected: "popup_icon_four_hig",
                unable: "popup_icon_four_unable",
                normal: "popup_icon_four_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          param_range: { min: 1, max: 4 },
          param_delta: 1,
        },
      ],
    },
    models: ["zhimi.fan.v2", "zhimi.fan.v3", "zhimi.fan.sa1", "zhimi.fan.za1"],
  },
  {
    props: [
      {
        format: "%.0f",
        prop_name: { en: "TDS", zh_HK: "TDS", zh_CN: "TDS", zh_TW: "TDS" },
        prop_value_type: [{ key: "value", type: "JSONObject" }, { index: 5, type: "JSONArray" }, { type: "int" }],
        prop_key: "event.pure_water_record",
        prop_unit: "mg/L",
        prop_extra: [
          {
            desc: { en: "Drinkable", zh_HK: "可飲用", zh_CN: "可饮用", zh_TW: "可飲用" },
            text_color: "#FF2DD1E2",
            param_range: { min: 0, max: 80 },
          },
          {
            desc: { en: "Undrinkable", zh_HK: "不可直飲", zh_CN: "不可直饮", zh_TW: "不可直飲" },
            text_color: "#FFE0AC15",
            param_range: { min: 81, max: 500 },
          },
        ],
        supportType: [1, 2, 3],
        ratio: 1,
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [{ supportGrid: 1, cardType: 7, prop_key: "event.pure_water_record" }],
    },
    models: [
      "yunmi.waterpurifier.v3",
      "yunmi.waterpuri.lx2",
      "yunmi.waterpuri.lx4",
      "yunmi.waterpuri.lx3",
      "yunmi.waterpurifier.v2",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.is_playing",
        supportType: [1],
        switchStatus: ["1"],
        prop_name: { en: "Switch", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "1", desc: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
          { value: "0", desc: { en: "Pause", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Mode", zh_HK: "音量調節", zh_CN: "音量调节", zh_TW: "音量調節" },
        prop_key: "prop.volume",
      },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 2,
          operation: [
            {
              param: [],
              method: "resume_song",
              prop_value: "0",
              button_name: { en: "Paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "btn_radio_play",
              },
            },
            {
              param: [],
              method: "pause_song",
              prop_value: "1",
              button_name: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.is_playing",
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_volume", disable_status: [{ key: "prop.current_status", value: "pause" }] }],
          prop_key: "prop.volume",
          param_type: [{ type: "JSONArray", index: 0 }, { type: "string" }],
          small_image: "seekbar_thumb_sound",
          param_range: { min: 0, max: 100 },
        },
      ],
    },
    models: ["jiqid.mistory.v1", "jiqid.mistory.v2"],
  },
  {
    props: [
      {
        prop_key: "prop.on",
        supportType: [1],
        switchStatus: ["true"],
        prop_name: { en: "Socket Power", zh_HK: "插座電源", zh_CN: "插座电源", zh_TW: "插座電源" },
        prop_extra: [
          { value: "true", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "false", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.usb_on",
        supportType: [1],
        switchStatus: ["true"],
        prop_name: { en: "USB Power", zh_HK: "USB電源", zh_CN: "USB电源", zh_TW: "USB電源" },
        prop_extra: [
          { value: "true", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "false", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: [],
              method: "set_on",
              prop_value: "false",
              button_name: { en: "Power", zh_HK: "插座電源", zh_CN: "插座电源", zh_TW: "插座電源" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: [],
              method: "set_off",
              prop_value: "true",
              button_name: { en: "Power", zh_HK: "插座電源", zh_CN: "插座电源", zh_TW: "插座電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.on",
        },
        {
          cardType: 1,
          operation: [
            {
              param: [],
              method: "set_usb_on",
              prop_value: "false",
              button_name: { en: "Power", zh_HK: "USB電源", zh_CN: "USB电源", zh_TW: "USB電源" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: [],
              method: "set_usb_off",
              prop_value: "true",
              button_name: { en: "Power", zh_HK: "USB電源", zh_CN: "USB电源", zh_TW: "USB電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.usb_on",
        },
      ],
    },
    models: ["chuangmi.plug.v1", "chuangmi.plug.v3"],
  },
  {
    props: [
      {
        prop_key: "prop.neutral_0",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["neutral_0", "on"],
              method: "toggle_plug",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_0", "off"],
              method: "toggle_plug",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "電源", zh_CN: "电源", zh_TW: "電源" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.neutral_0",
        },
      ],
    },
    models: ["lumi.plug.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.neutral_0",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["neutral_0", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_0", "off"],
              method: "toggle_ctrl_neutral",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.neutral_0",
        },
      ],
    },
    models: ["lumi.ctrl_neutral1.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.neutral_0",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.neutral_1",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        {
          cardType: 1,
          operation: [
            {
              param: ["neutral_0", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_0", "off"],
              method: "toggle_ctrl_neutral",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "左鍵開關", zh_CN: "左键开关", zh_TW: "左鍵開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.neutral_0",
        },
        {
          cardType: 1,
          operation: [
            {
              param: ["neutral_1", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["neutral_1", "off"],
              method: "toggle_ctrl_neutral",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "右鍵開關", zh_CN: "右键开关", zh_TW: "右鍵開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.neutral_1",
        },
      ],
    },
    models: ["lumi.ctrl_neutral2.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_extra: [
          { desc: { en: "Close", zh_HK: "關閉", zh_CN: "关闭", zh_TW: "關閉" }, value: "on" },
          { desc: { en: "Open", zh_HK: "打開", zh_CN: "打开", zh_TW: "打開" }, value: "off" },
        ],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
      {
        supportType: [1],
        prop_key: "prop.bri",
        prop_name: { en: "Set bright", zh_HK: "亮度調節", zh_CN: "亮度调节", zh_TW: "亮度調節" },
      },
      {
        supportType: [1],
        prop_key: "prop.cct",
        prop_name: { en: "Set cct", zh_HK: "色溫調節", zh_CN: "色温调节", zh_TW: "色溫調節" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 11,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_cct", disable_status: [{ key: "prop.power", value: "off" }] }],
          prop_key: "prop.cct",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "",
          param_range: { min: 1, max: 100 },
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          prop_key: "prop.bri",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "seekbar_thumb_light",
          param_range: { min: 1, max: 100 },
        },
      ],
    },
    models: ["philips.light.bulb"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_extra: [
          { desc: { en: "Close", zh_HK: "關閉", zh_CN: "关闭", zh_TW: "關閉" }, value: "on" },
          { desc: { en: "Open", zh_HK: "打開", zh_CN: "打开", zh_TW: "打開" }, value: "off" },
        ],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
      ],
    },
    models: ["philips.light.mono1", "philips.light.sread1"],
  },
  {
    props: [
      {
        supportType: [1],
        subProps: [
          {
            prop_key: "state",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "state", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "當前狀態", zh_CN: "当前状态", zh_TW: "當前狀態" },
            prop_extra: [
              { value: 2, desc: { en: "Dormant", zh_HK: "休眠", zh_CN: "休眠", zh_TW: "休眠" } },
              {
                value: 3,
                desc: { en: "Wait instruction", zh_HK: "等待指令", zh_CN: "等待指令", zh_TW: "等待指令" },
              },
              { value: 5, desc: { en: "Sweeping", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" } },
              { value: 6, desc: { en: "Return charging", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" } },
              {
                value: 7,
                desc: { en: "Remote control", zh_HK: "遙控中", zh_CN: "遥控中", zh_TW: "遙控中" },
              },
              {
                value: 8,
                desc: { en: "Charging in progress", zh_HK: "充電中", zh_CN: "充电中", zh_TW: "充電中" },
              },
              {
                value: 9,
                desc: { en: "Charging error", zh_HK: "充電報錯", zh_CN: "充电报错", zh_TW: "充電報錯" },
              },
              { value: 10, desc: { en: "Pause", zh_HK: "暫停", zh_CN: "暂停", zh_TW: "暫停" } },
              {
                value: 11,
                desc: { en: "Partial sweeping", zh_HK: "局部清掃", zh_CN: "局部清扫", zh_TW: "局部清掃" },
              },
              { value: 12, desc: { en: "Error", zh_HK: "報錯", zh_CN: "报错", zh_TW: "報錯" } },
              { value: 14, desc: { en: "Upgrading", zh_HK: "升級中", zh_CN: "升级中", zh_TW: "升級中" } },
              {
                value: 16,
                desc: {
                  en: "Going to the target point",
                  zh_HK: "正在行進至目標點",
                  zh_CN: "正在行进至目标点",
                  zh_TW: "正在行進至目標點",
                },
              },
              {
                value: 17,
                desc: {
                  en: "Zoned cleanup",
                  zh_HK: "正在劃區清掃",
                  zh_CN: "正在划区清扫",
                  zh_TW: "正在劃區清掃",
                },
              },
            ],
          },
          {
            prop_key: "fan_power",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "fan_power", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "狀態", zh_CN: "状态", zh_TW: "狀態" },
          },
        ],
        prop_key: "event.status",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        { prop_key: "event.status", sub_prop_key: "state", cardType: 8 },
        {
          supportGrid: 1,
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 5,
              button_name: { en: "Pause", zh_HK: "清掃中", zh_CN: "清扫中", zh_TW: "清掃中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_clean_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
                { key: "state", value: 17 },
              ],
            },
            {
              param: [],
              method: "app_start",
              prop_value: 10,
              button_name: { en: "Start clean", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" },
              button_image: {
                selected: "popup_icon_clean_hig",
                unable: "popup_icon_clean_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 6 },
                { key: "state", value: 7 },
                { key: "state", value: 11 },
                { key: "state", value: 14 },
                { key: "state", value: 16 },
                { key: "state", value: 17 },
              ],
            },
          ],
        },
        {
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 6,
              button_name: { en: "Pause", zh_HK: "回充中", zh_CN: "回充中", zh_TW: "回充中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_stow_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
                { key: "state", value: 17 },
              ],
            },
            {
              param: [],
              method: "app_charge",
              prop_value: 10,
              button_name: { en: "Charge", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" },
              button_image: {
                selected: "popup_icon_stow_hig",
                unable: "popup_icon_stow_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 7 },
                { key: "state", value: 8 },
                { key: "state", value: 9 },
                { key: "state", value: 11 },
                { key: "state", value: 12 },
                { key: "state", value: 14 },
                { key: "state", value: 16 },
                { key: "state", value: 17 },
              ],
            },
          ],
        },
      ],
    },
    models: ["roborock.vacuum.s5", "roborock.sweeper.s5v2", "roborock.sweeper.s5v3"],
  },
  {
    props: [
      {
        supportType: [1],
        subProps: [
          {
            prop_key: "state",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "state", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "當前狀態", zh_CN: "当前状态", zh_TW: "當前狀態" },
            prop_extra: [
              { value: 2, desc: { en: "Dormant", zh_HK: "休眠", zh_CN: "休眠", zh_TW: "休眠" } },
              {
                value: 3,
                desc: { en: "Wait instruction", zh_HK: "等待指令", zh_CN: "等待指令", zh_TW: "等待指令" },
              },
              { value: 5, desc: { en: "Sweeping", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" } },
              { value: 6, desc: { en: "Return charging", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" } },
              {
                value: 7,
                desc: { en: "Remote control", zh_HK: "遙控中", zh_CN: "遥控中", zh_TW: "遙控中" },
              },
              {
                value: 8,
                desc: { en: "Charging in progress", zh_HK: "充電中", zh_CN: "充电中", zh_TW: "充電中" },
              },
              {
                value: 9,
                desc: { en: "Charging error", zh_HK: "充電報錯", zh_CN: "充电报错", zh_TW: "充電報錯" },
              },
              { value: 10, desc: { en: "Pause", zh_HK: "暫停", zh_CN: "暂停", zh_TW: "暫停" } },
              {
                value: 11,
                desc: { en: "Partial sweeping", zh_HK: "局部清掃", zh_CN: "局部清扫", zh_TW: "局部清掃" },
              },
              { value: 12, desc: { en: "Error", zh_HK: "報錯", zh_CN: "报错", zh_TW: "報錯" } },
              { value: 14, desc: { en: "Upgrading", zh_HK: "升級中", zh_CN: "升级中", zh_TW: "升級中" } },
            ],
          },
          {
            prop_key: "fan_power",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "fan_power", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "狀態", zh_CN: "状态", zh_TW: "狀態" },
          },
        ],
        prop_key: "event.status",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        { prop_key: "event.status", sub_prop_key: "state", cardType: 8 },
        {
          supportGrid: 1,
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 5,
              button_name: { en: "Pause", zh_HK: "清掃中", zh_CN: "清扫中", zh_TW: "清掃中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_clean_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
              ],
            },
            {
              param: [],
              method: "app_start",
              prop_value: 10,
              button_name: { en: "Start clean", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" },
              button_image: {
                selected: "popup_icon_clean_hig",
                unable: "popup_icon_clean_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 6 },
                { key: "state", value: 7 },
                { key: "state", value: 11 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
        {
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 6,
              button_name: { en: "Pause", zh_HK: "回充中", zh_CN: "回充中", zh_TW: "回充中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_stow_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
              ],
            },
            {
              param: [],
              method: "app_charge",
              prop_value: 10,
              button_name: { en: "Charge", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" },
              button_image: {
                selected: "popup_icon_stow_hig",
                unable: "popup_icon_stow_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 7 },
                { key: "state", value: 8 },
                { key: "state", value: 9 },
                { key: "state", value: 11 },
                { key: "state", value: 12 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
      ],
    },
    models: ["roborock.vacuum.e2", "roborock.sweeper.e2v2", "roborock.sweeper.e2v3"],
  },
  {
    props: [
      {
        supportType: [1],
        subProps: [
          {
            prop_key: "state",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "state", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "當前狀態", zh_CN: "当前状态", zh_TW: "當前狀態" },
            prop_extra: [
              { value: 2, desc: { en: "Dormant", zh_HK: "休眠", zh_CN: "休眠", zh_TW: "休眠" } },
              {
                value: 3,
                desc: { en: "Wait instruction", zh_HK: "等待指令", zh_CN: "等待指令", zh_TW: "等待指令" },
              },
              { value: 5, desc: { en: "Sweeping", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" } },
              { value: 6, desc: { en: "Return charging", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" } },
              {
                value: 7,
                desc: { en: "Remote control", zh_HK: "遙控中", zh_CN: "遥控中", zh_TW: "遙控中" },
              },
              {
                value: 8,
                desc: { en: "Charging in progress", zh_HK: "充電中", zh_CN: "充电中", zh_TW: "充電中" },
              },
              {
                value: 9,
                desc: { en: "Charging error", zh_HK: "充電報錯", zh_CN: "充电报错", zh_TW: "充電報錯" },
              },
              { value: 10, desc: { en: "Pause", zh_HK: "暫停", zh_CN: "暂停", zh_TW: "暫停" } },
              {
                value: 11,
                desc: { en: "Partial sweeping", zh_HK: "局部清掃", zh_CN: "局部清扫", zh_TW: "局部清掃" },
              },
              { value: 12, desc: { en: "Error", zh_HK: "報錯", zh_CN: "报错", zh_TW: "報錯" } },
              { value: 14, desc: { en: "Upgrading", zh_HK: "升級中", zh_CN: "升级中", zh_TW: "升級中" } },
            ],
          },
          {
            prop_key: "fan_power",
            prop_value_type: [
              { key: "value", type: "JSONObject" },
              { index: 0, type: "JSONArray" },
              { key: "fan_power", type: "JSONObject" },
              { type: "int" },
            ],
            prop_name: { en: "Status", zh_HK: "狀態", zh_CN: "状态", zh_TW: "狀態" },
          },
        ],
        prop_key: "event.status",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        { prop_key: "event.status", sub_prop_key: "state", cardType: 8 },
        {
          supportGrid: 1,
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 5,
              button_name: { en: "Pause", zh_HK: "清掃中", zh_CN: "清扫中", zh_TW: "清掃中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_clean_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
              ],
            },
            {
              param: [],
              method: "app_start",
              prop_value: 10,
              button_name: { en: "Start clean", zh_HK: "清掃", zh_CN: "清扫", zh_TW: "清掃" },
              button_image: {
                selected: "popup_icon_clean_hig",
                unable: "popup_icon_clean_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 6 },
                { key: "state", value: 7 },
                { key: "state", value: 11 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
        {
          prop_key: "event.status",
          cardType: 2,
          sub_prop_key: "state",
          operation: [
            {
              param: [],
              method: "app_pause",
              prop_value: 6,
              button_name: { en: "Pause", zh_HK: "回充中", zh_CN: "回充中", zh_TW: "回充中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "popup_icon_stow_hig",
              },
              enable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 6 },
              ],
            },
            {
              param: [],
              method: "app_charge",
              prop_value: 10,
              button_name: { en: "Charge", zh_HK: "回充", zh_CN: "回充", zh_TW: "回充" },
              button_image: {
                selected: "popup_icon_stow_hig",
                unable: "popup_icon_stow_unable",
                normal: "btn_radio_pause",
              },
              disable_status: [
                { key: "state", value: 5 },
                { key: "state", value: 7 },
                { key: "state", value: 8 },
                { key: "state", value: 9 },
                { key: "state", value: 11 },
                { key: "state", value: 12 },
                { key: "state", value: 14 },
              ],
            },
          ],
        },
      ],
    },
    models: ["roborock.vacuum.c1", "roborock.sweeper.c1v2", "roborock.sweeper.c1v3"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_extra: [
          { desc: { en: "Close", zh_HK: "關閉", zh_CN: "关闭", zh_TW: "關閉" }, value: "on" },
          { desc: { en: "Open", zh_HK: "打開", zh_CN: "打开", zh_TW: "打開" }, value: "off" },
        ],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
      {
        supportType: [1],
        prop_key: "prop.bright",
        prop_name: { en: "Set Daylight", zh_HK: "日觀調節", zh_CN: "日光调节", zh_TW: "日光調節" },
      },
      {
        supportType: [1],
        prop_key: "prop.nl_br",
        prop_name: { en: "Set Moonlight", zh_HK: "月光調節", zh_CN: "月光调节", zh_TW: "月光調節" },
      },
      {
        supportType: [1],
        prop_key: "prop.night_light",
        prop_name: { en: "Set Moonlight", zh_HK: "月光調節", zh_CN: "月光调节", zh_TW: "月光調節" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          prop_key: "prop.bright",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "seekbar_thumb_light",
          param_range: { min: 1, max: 100 },
        },
        {
          cardType: 5,
          end_color: "",
          start_color: "",
          operation: [
            {
              method: "set_bright",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.nl_br", value: "0" },
              ],
            },
          ],
          prop_key: "prop.nl_br",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
          small_image: "seekbar_thumb_moon",
          param_range: { min: 1, max: 100 },
        },
      ],
    },
    models: [
      "yeelink.light.ceiling1",
      "yeelink.light.ceiling2",
      "yeelink.light.ceiling3",
      "yeelink.light.ceiling4",
      "yeelink.light.ceiling5",
      "yeelink.light.ceiling6",
      "yeelink.light.ceiling7",
      "yeelink.light.ceiling8",
      "yeelink.light.ceiling9",
      "yeelink.light.ceiling10",
    ],
  },
  {
    props: [
      {
        prop_key: "prop.fm_current_status",
        supportType: [1],
        switchStatus: ["run"],
        prop_name: { en: "Switch", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "run", desc: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
          { value: "pause", desc: { en: "Pause", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" } },
        ],
      },
      {
        prop_key: "prop.light",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Light", zh_HK: "夜燈", zh_CN: "夜灯", zh_TW: "夜燈" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.arming",
        supportType: [1],
        switchStatus: ["on", "oning"],
        prop_name: { en: "Arming", zh_HK: "警戒", zh_CN: "警戒", zh_TW: "警戒" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        {
          cardType: 1,
          operation: [
            {
              param: ["off"],
              method: "play_fm",
              prop_value: "run",
              button_name: { en: "Playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "btn_radio_play",
              },
            },
            {
              param: ["on"],
              method: "play_fm",
              prop_value: "pause",
              button_name: { en: "Paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.fm_current_status",
        },
        {
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "toggle_light",
              prop_value: "off",
              button_name: { en: "Light", zh_HK: "夜燈", zh_CN: "夜灯", zh_TW: "夜燈" },
              button_image: {
                selected: "btn_gatewaylight_on",
                unable: "btn_gatewaylight_unable",
                normal: "btn_gatewaylight_off",
              },
            },
            {
              param: ["off"],
              method: "toggle_light",
              prop_value: "on",
              button_name: { en: "Light", zh_HK: "夜燈", zh_CN: "夜灯", zh_TW: "夜燈" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.light",
        },
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_arming",
              prop_value: "off",
              button_name: { en: "Arming", zh_HK: "警戒", zh_CN: "警戒", zh_TW: "警戒" },
              button_image: { selected: "btn_alert_on", unable: "btn_alert_unable", normal: "btn_alert_off" },
            },
            {
              param: ["oning"],
              method: "set_arming",
              prop_value: "off",
              button_name: { en: "Arming", zh_HK: "警戒", zh_CN: "警戒", zh_TW: "警戒" },
              button_image: { selected: "", normal: "" },
            },
            {
              param: ["off"],
              method: "set_arming",
              prop_value: "on",
              button_name: { en: "Arming", zh_HK: "警戒", zh_CN: "警戒", zh_TW: "警戒" },
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.arming",
        },
      ],
    },
    models: ["lumi.gateway.v3"],
  },
  {
    props: [
      {
        prop_key: "prop.pm25",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        prop_key: "prop.co2e",
        prop_unit: "ppm",
        supportType: [1, 2],
        prop_name: { en: "CO₂e", zh_HK: "CO₂e", zh_CN: "CO₂e", zh_TW: "CO₂e" },
        ratio: 1,
        format: "%.0f",
      },
      {
        prop_key: "prop.tvoc",
        supportType: [1, 2],
        prop_name: { en: "tVOC", zh_HK: "tVOC", zh_CN: "tVOC", zh_TW: "tVOC" },
        depend_compute: {
          depend_prop_key: "prop.unit_tvoc",
          depend_formulas: [
            { prop_unit: "ppb", value: "ppb", formula: [{ type: "*", value: "203" }], format: "%.0f" },
            { prop_unit: "ppm", value: "ppm", formula: [{ type: "*", value: "0.203" }], format: "%.3f" },
            { value: "mg_m3", format: "%.3f", prop_unit: "mg/m³" },
          ],
        },
      },
      {
        prop_key: "prop.temperature",
        supportType: [1, 2],
        prop_name: { en: "TEMP", zh_HK: "溫度", zh_CN: "温度", zh_TW: "溫度" },
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 40 } },
        ],
        depend_compute: {
          depend_prop_key: "prop.temperature_unit",
          depend_formulas: [
            {
              prop_unit: "℉",
              value: "f",
              formula: [
                { type: "*", value: "1.8" },
                { type: "+", value: "32" },
              ],
              format: "%.0f",
            },
            { value: "c", format: "%.0f", prop_unit: "℃" },
          ],
        },
      },
      {
        prop_key: "prop.humidity",
        prop_unit: "%",
        supportType: [1, 2],
        prop_name: { en: "Humidity", zh_HK: "濕度", zh_CN: "湿度", zh_TW: "濕度" },
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
      { prop_key: "prop.temperature_unit" },
      { prop_key: "prop.unit_tvoc" },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.pm25" },
        { cardType: 7, prop_key: "prop.temperature" },
        { cardType: 7, prop_key: "prop.humidity" },
      ],
    },
    models: ["cgllc.airmonitor.b1"],
  },
  {
    props: [
      {
        prop_key: "prop.4100",
        prop_unit: "℃",
        supportType: [1, 2, 3],
        prop_name: { en: "TEMP", zh_HK: "溫度", zh_CN: "温度", zh_TW: "溫度" },
        ratio: 0.1,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 40 } },
        ],
      },
      {
        prop_key: "prop.4102",
        prop_unit: "%",
        supportType: [1, 2, 3],
        prop_name: { en: "Humidity", zh_HK: "濕度", zh_CN: "湿度", zh_TW: "濕度" },
        ratio: 0.1,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
      { prop_key: "prop.4109" },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.4100" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.4102" },
      ],
    },
    models: ["cleargrass.sensor_ht.dk1"],
  },
  {
    props: [
      {
        prop_key: "prop.4104",
        prop_unit: "%",
        supportType: [1, 2, 3],
        prop_name: { en: "Water", zh_HK: "水分", zh_CN: "水分", zh_TW: "水分" },
        format: "%.0f",
      },
      {
        prop_key: "prop.4105",
        prop_unit: "µs/cm",
        supportType: [1, 2],
        prop_name: { en: "Fertility", zh_HK: "肥力", zh_CN: "肥力", zh_TW: "肥力" },
        format: "%.0f",
      },
      {
        prop_key: "prop.4103",
        prop_unit: "lux",
        supportType: [1, 2],
        prop_name: { en: "Light", zh_HK: "光照", zh_CN: "光照", zh_TW: "光照" },
        format: "%.0f",
      },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.4104" },
        { cardType: 7, prop_key: "prop.4103" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.4105" },
      ],
    },
    models: ["hhcc.plantmonitor.v1"],
  },
  {
    props: [
      {
        prop_key: "prop.4104",
        prop_unit: "%",
        supportType: [1, 2],
        prop_name: { en: "Water", zh_HK: "水分", zh_CN: "水分", zh_TW: "水分" },
        format: "%.0f",
      },
      {
        prop_key: "prop.4105",
        prop_unit: "µs/cm",
        supportType: [1, 2],
        prop_name: { en: "Fertility", zh_HK: "肥力", zh_CN: "肥力", zh_TW: "肥力" },
        format: "%.0f",
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.4104" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.4105" },
      ],
    },
    models: ["hhcc.bleflowerpot.v2"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
        prop_extra: [
          { value: "on", desc: { en: "On", zh_HK: "開", zh_CN: "开", zh_TW: "開" } },
          { value: "off", desc: { en: "Off", zh_HK: "關", zh_CN: "关", zh_TW: "關" } },
        ],
      },
      {
        prop_key: "prop.aqi",
        supportType: [1, 2],
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
        prop_extra: [
          {
            text_color: "#FF30C480",
            param_range: { min: 0, max: 35 },
            desc: { en: "Excellent", zh_HK: "優", zh_CN: "优", zh_TW: "優" },
          },
          {
            text_color: "#FF76C430",
            param_range: { min: 36, max: 75 },
            desc: { en: "Fine", zh_HK: "良", zh_CN: "良", zh_TW: "良" },
          },
          {
            text_color: "#FFE6BB25",
            param_range: { min: 76, max: 115 },
            desc: { en: "Light pollution", zh_HK: "輕度污染", zh_CN: "轻度污染", zh_TW: "輕度污染" },
          },
          {
            text_color: "#FFE67D19",
            param_range: { min: 116, max: 150 },
            desc: { en: "Moderate pollution", zh_HK: "中度污染", zh_CN: "中度污染", zh_TW: "中度污染" },
          },
          {
            text_color: "#CCF13312",
            param_range: { min: 151, max: 250 },
            desc: { en: "Heavy pollution", zh_HK: "重度污染", zh_CN: "重度污染", zh_TW: "重度污染" },
          },
          {
            text_color: "#E5B60E11",
            param_range: { min: 251, max: 1000 },
            desc: { en: "Serious pollution", zh_HK: "嚴重污染", zh_CN: "严重污染", zh_TW: "嚴重污染" },
          },
        ],
        format: "%.0f",
      },
      {
        supportType: [1],
        prop_key: "prop.mode",
        prop_name: { en: "Mode", zh_HK: "模式", zh_CN: "模式", zh_TW: "模式" },
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 7, prop_key: "prop.aqi" },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { en: "Automatic", zh_HK: "自動", zh_CN: "自动", zh_TW: "自動" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["silent"],
              method: "set_mode",
              prop_value: "silent",
              button_name: { en: "Sleep", zh_HK: "睡眠", zh_CN: "睡眠", zh_TW: "睡眠" },
              button_image: { selected: "btn_sleep_on", unable: "btn_sleep_unable", normal: "btn_sleep_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["interval"],
              method: "set_mode",
              prop_value: "interval",
              button_name: { en: "Interval", zh_HK: "間歇", zh_CN: "间歇", zh_TW: "間歇" },
              button_image: {
                selected: "btn_intermittent_on",
                unable: "btn_intermittent_unable",
                normal: "btn_intermittent_off",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["zhimi.airfresh.va2"],
  },
  {
    props: [
      {
        prop_key: "prop.wash_process",
        supportType: [1],
        prop_name: { zh_CN: "当前状态", en: "status" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "空闲中", en: "Idle" } },
          { value: "1", desc: { zh_CN: "洗涤中", en: "Washing" } },
          { value: "2", desc: { zh_CN: "洗涤中", en: "Washing" } },
          { value: "3", desc: { zh_CN: "洗涤中", en: "Washing" } },
          { value: "4", desc: { zh_CN: "洗涤中", en: "Washing" } },
          { value: "5", desc: { zh_CN: "洗涤中", en: "Washing" } },
          { value: "6", desc: { zh_CN: "洗涤结束", en: "Finished" } },
        ],
      },
      {
        prop_key: "prop.ldj_state",
        supportType: [1],
        prop_name: { zh_CN: "亮碟剂", en: "Rinse Agent" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "已耗尽", en: "Depleted" } },
          { value: "1", desc: { zh_CN: "未耗尽", en: "Ample" } },
        ],
      },
      {
        prop_key: "prop.salt_state",
        supportType: [1],
        prop_name: { zh_CN: "软水盐", en: "Salt" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "已耗尽", en: "Depleted" } },
          { value: "1", desc: { zh_CN: "未耗尽", en: "Ample" } },
        ],
      },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        { cardType: 8, prop_key: "prop.wash_process" },
        { cardType: 8, prop_key: "prop.ldj_state" },
        { cardType: 8, prop_key: "prop.salt_state" },
      ],
    },
    models: ["viomi.dishwasher.v01"],
  },
  {
    props: [
      {
        prop_key: "prop.temperature",
        prop_unit: "℃",
        supportType: [1, 2],
        prop_name: { en: "temperature", zh_HK: "體溫", zh_CN: "体温", zh_TW: "體溫" },
        ratio: 1,
        format: "%.2f",
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 7, prop_key: "prop.temperature" }] },
    models: ["miaomiaoce.thermo.t01"],
  },
  {
    props: [
      {
        prop_key: "prop.MicrophoneMute",
        supportType: [1],
        switchStatus: ["false"],
        prop_name: { en: "Microphone", zh_HK: "麦克风", zh_CN: "麦克风", zh_TW: "麦克风" },
        prop_extra: [
          { value: "true", desc: { en: "Off", zh_HK: "关闭", zh_CN: "关闭", zh_TW: "关闭" } },
          { value: "false", desc: { en: "On", zh_HK: "打开", zh_CN: "打开", zh_TW: "打开" } },
        ],
      },
      {
        prop_key: "prop.SpeakerRate",
        supportType: [1],
        switchStatus: ["1"],
        prop_name: { en: "player", zh_HK: "播放器", zh_CN: "播放器", zh_TW: "播放器" },
        prop_extra: [
          { value: "0", desc: { en: "pause", zh_HK: "已暂停", zh_CN: "已暂停", zh_TW: "已暂停" } },
          { value: "1", desc: { en: "play", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Mode", zh_HK: "音量", zh_CN: "音量", zh_TW: "音量" },
        prop_key: "prop.SpeakerVolume",
      },
    ],
    cards: {
      min_firmware_version: "1.2.6",
      layout_type: 3,
      card_items: [
        {
          cardType: 2,
          operation: [
            {
              param: [1],
              method: "set_speaker_SpeakerRate",
              prop_value: 0,
              button_name: { en: "paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: {
                selected: "btn_radio_play",
                unable: "btn_radio_unable",
                normal: "btn_radio_pause",
              },
            },
            {
              param: [0],
              method: "set_speaker_SpeakerRate",
              prop_value: 1,
              button_name: { en: "playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.SpeakerRate",
        },
        {
          cardType: 2,
          operation: [
            {
              param: [true],
              method: "set_microphone_MicrophoneMute",
              prop_value: false,
              button_name: { en: "On", zh_HK: "麥克已啓用", zh_CN: "麦克已启用", zh_TW: "麥克已啓用" },
              button_image: {
                selected: "btn_close_mic_off",
                unable: "btn_close_mic_disable",
                normal: "btn_close_mic_on",
              },
            },
            {
              param: [false],
              method: "set_microphone_MicrophoneMute",
              prop_value: true,
              button_name: { en: "Off", zh_HK: "麥克已禁用", zh_CN: "麦克已禁用", zh_TW: "麥克已禁用" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.MicrophoneMute",
        },
        {
          prop_key: "prop.SpeakerVolume",
          cardType: 4,
          operation: [{ method: "set_speaker_SpeakerVolume" }],
          param_range: { min: 1, max: 100 },
          param_delta: 10,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["xiaomi.wifispeaker.lx01"],
  },
  {
    props: [
      {
        prop_key: "prop.MicrophoneMute",
        supportType: [1],
        switchStatus: ["false"],
        prop_name: { en: "Microphone", zh_HK: "麦克风", zh_CN: "麦克风", zh_TW: "麦克风" },
        prop_extra: [
          { value: true, desc: { en: "Off", zh_HK: "关闭", zh_CN: "关闭", zh_TW: "关闭" } },
          { value: false, desc: { en: "On", zh_HK: "打开", zh_CN: "打开", zh_TW: "打开" } },
        ],
      },
      {
        prop_key: "prop.SpeakerRate",
        supportType: [1],
        switchStatus: ["1"],
        prop_name: { en: "player", zh_HK: "播放器", zh_CN: "播放器", zh_TW: "播放器" },
        prop_extra: [
          { value: "0", desc: { en: "pause", zh_HK: "已暂停", zh_CN: "已暂停", zh_TW: "已暂停" } },
          { value: "1", desc: { en: "play", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Mode", zh_HK: "音量", zh_CN: "音量", zh_TW: "音量" },
        prop_key: "prop.SpeakerVolume",
      },
    ],
    cards: {
      min_firmware_version: "1.20.1",
      layout_type: 3,
      card_items: [
        {
          cardType: 2,
          operation: [
            {
              param: [1],
              method: "set_speaker_SpeakerRate",
              prop_value: 0,
              button_name: { en: "paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: {
                selected: "btn_radio_play",
                unable: "btn_radio_unable",
                normal: "btn_radio_pause",
              },
            },
            {
              param: [0],
              method: "set_speaker_SpeakerRate",
              prop_value: 1,
              button_name: { en: "playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.SpeakerRate",
        },
        {
          cardType: 2,
          operation: [
            {
              param: [true],
              method: "set_microphone_MicrophoneMute",
              prop_value: false,
              button_name: { en: "On", zh_HK: "麥克已啓用", zh_CN: "麦克已启用", zh_TW: "麥克已啓用" },
              button_image: {
                selected: "btn_close_mic_off",
                unable: "btn_close_mic_disable",
                normal: "btn_close_mic_on",
              },
            },
            {
              param: [false],
              method: "set_microphone_MicrophoneMute",
              prop_value: true,
              button_name: { en: "Off", zh_HK: "麥克已禁用", zh_CN: "麦克已禁用", zh_TW: "麥克已禁用" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.MicrophoneMute",
        },
        {
          prop_key: "prop.SpeakerVolume",
          cardType: 4,
          operation: [{ method: "set_speaker_SpeakerVolume" }],
          param_range: { min: 1, max: 100 },
          param_delta: 10,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["xiaomi.wifispeaker.s12"],
  },
  {
    props: [
      {
        prop_key: "prop.MicrophoneMute",
        supportType: [1],
        switchStatus: ["false"],
        prop_name: { en: "Microphone", zh_HK: "麦克风", zh_CN: "麦克风", zh_TW: "麦克风" },
        prop_extra: [
          { value: "true", desc: { en: "Off", zh_HK: "关闭", zh_CN: "关闭", zh_TW: "关闭" } },
          { value: "false", desc: { en: "On", zh_HK: "打开", zh_CN: "打开", zh_TW: "打开" } },
        ],
      },
      {
        prop_key: "prop.SpeakerRate",
        supportType: [1],
        switchStatus: ["1"],
        prop_name: { en: "player", zh_HK: "播放器", zh_CN: "播放器", zh_TW: "播放器" },
        prop_extra: [
          { value: "0", desc: { en: "pause", zh_HK: "已暂停", zh_CN: "已暂停", zh_TW: "已暂停" } },
          { value: "1", desc: { en: "play", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" } },
        ],
      },
      {
        supportType: [1],
        prop_name: { en: "Mode", zh_HK: "音量", zh_CN: "音量", zh_TW: "音量" },
        prop_key: "prop.SpeakerVolume",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          cardType: 2,
          operation: [
            {
              param: [1],
              method: "set_speaker_SpeakerRate",
              prop_value: 0,
              button_name: { en: "paused", zh_HK: "已暫停", zh_CN: "已暂停", zh_TW: "已暫停" },
              button_image: {
                selected: "btn_radio_play",
                unable: "btn_radio_unable",
                normal: "btn_radio_pause",
              },
            },
            {
              param: [0],
              method: "set_speaker_SpeakerRate",
              prop_value: 1,
              button_name: { en: "playing", zh_HK: "播放中", zh_CN: "播放中", zh_TW: "播放中" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.SpeakerRate",
        },
        {
          cardType: 2,
          operation: [
            {
              param: [true],
              method: "set_microphone_MicrophoneMute",
              prop_value: false,
              button_name: { en: "On", zh_HK: "麥克已啓用", zh_CN: "麦克已启用", zh_TW: "麥克已啓用" },
              button_image: {
                selected: "btn_close_mic_off",
                unable: "btn_close_mic_disable",
                normal: "btn_close_mic_on",
              },
            },
            {
              param: [false],
              method: "set_microphone_MicrophoneMute",
              prop_value: true,
              button_name: { en: "Off", zh_HK: "麥克已禁用", zh_CN: "麦克已禁用", zh_TW: "麥克已禁用" },
              button_image: { selected: "", unable: "", normal: "" },
            },
          ],
          prop_key: "prop.MicrophoneMute",
        },
        {
          prop_key: "prop.SpeakerVolume",
          cardType: 4,
          operation: [{ method: "set_speaker_SpeakerVolume" }],
          param_range: { min: 1, max: 100 },
          param_delta: 10,
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["onemore.wifispeaker.sm4"],
  },
  {
    props: [
      {
        prop_key: "prop.setup_tempe",
        prop_unit: "℃",
        supportType: [1, 2],
        prop_name: { zh_CN: "出水温度", en: "WaterTemp." },
        ratio: 1,
        format: "%.0f",
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 100 } },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 7, prop_key: "prop.setup_tempe" }] },
    models: ["yunmi.kettle.r2", "yunmi.kettle.r3"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.tar_temp",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "温度", en: "temp" },
        prop_extra: [
          { desc: { zh_CN: "低温", en: "Lower" }, param_range: { min: 16, max: 20 } },
          { desc: { zh_CN: "室温", en: "Normal" }, param_range: { min: 20, max: 26 } },
          { desc: { zh_CN: "高温", en: "High" }, param_range: { min: 26, max: 31 } },
        ],
        format: "%.1f",
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        prop_name: { zh_CN: "挡位选择", en: "Mode" },
        prop_extra: [
          { value: "auto", desc: { zh_CN: "自动", en: "Auto" } },
          { value: "cool", desc: { zh_CN: "制冷", en: "Cool" } },
          { value: "dry", desc: { zh_CN: "除湿", en: "Dry" } },
          { value: "wind", desc: { zh_CN: "送风", en: "Wind" } },
          { value: "heat", desc: { zh_CN: "制热", en: "Heat" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { zh_CN: "自动", en: "Auto" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["cool"],
              method: "set_mode",
              prop_value: "cool",
              button_name: { zh_CN: "制冷", en: "Cool" },
              button_image: {
                selected: "popup_icon_cold_hig",
                unable: "popup_icon_cold_unable",
                normal: "popup_icon_cold_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["heat"],
              method: "set_mode",
              prop_value: "heat",
              button_name: { zh_CN: "制热", en: "Heat" },
              button_image: {
                selected: "popup_icon_sun_hig",
                unable: "popup_icon_sun_unable",
                normal: "popup_icon_sun_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
        {
          prop_key: "prop.tar_temp",
          cardType: 4,
          operation: [
            {
              method: "set_tar_temp",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.mode", value: "auto" },
              ],
            },
          ],
          param_range: { min: 16, max: 31 },
          param_delta: 0.5,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "double" }],
        },
      ],
    },
    models: ["aden.aircondition.a2"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.tar_temp",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "温度", en: "temperature" },
        prop_extra: [
          { desc: { zh_CN: "低温", en: "Lower" }, param_range: { min: 16, max: 20 } },
          { desc: { zh_CN: "室温", en: "Normal" }, param_range: { min: 20, max: 26 } },
          { desc: { zh_CN: "高温", en: "High" }, param_range: { min: 26, max: 31 } },
        ],
      },
      {
        prop_key: "prop.mode",
        supportType: [1],
        prop_name: { zh_CN: "档位选择", en: "Mode" },
        prop_extra: [
          { value: "auto", desc: { zh_CN: "自动", en: "Auto" } },
          { value: "cool", desc: { zh_CN: "制冷", en: "Cool" } },
          { value: "dry", desc: { zh_CN: "除湿", en: "Dry" } },
          { value: "wind", desc: { zh_CN: "送风", en: "Wind" } },
          { value: "heat", desc: { zh_CN: "制热", en: "Heat" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        {
          cardType: 3,
          operation: [
            {
              param: ["auto"],
              method: "set_mode",
              prop_value: "auto",
              button_name: { zh_CN: "自动", en: "Auto" },
              button_image: { selected: "btn_auto_on", unable: "btn_auto_unable", normal: "btn_auto_off" },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["cool"],
              method: "set_mode",
              prop_value: "cool",
              button_name: { zh_CN: "制冷", en: "Cool" },
              button_image: {
                selected: "popup_icon_cold_hig",
                unable: "popup_icon_cold_unable",
                normal: "popup_icon_cold_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
            {
              param: ["heat"],
              method: "set_mode",
              prop_value: "heat",
              button_name: { zh_CN: "制热", en: "Heat" },
              button_image: {
                selected: "popup_icon_sun_hig",
                unable: "popup_icon_sun_unable",
                normal: "popup_icon_sun_nor",
              },
              disable_status: [{ key: "prop.power", value: "off" }],
            },
          ],
          prop_key: "prop.mode",
        },
        {
          prop_key: "prop.tar_temp",
          cardType: 4,
          operation: [
            {
              method: "set_tar_temp",
              disable_status: [
                { key: "prop.power", value: "off" },
                { key: "prop.mode", value: "auto" },
              ],
            },
          ],
          param_range: { min: 16, max: 31 },
          param_delta: 1,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "int" }],
        },
      ],
    },
    models: ["aden.aircondition.a1"],
  },
  {
    props: [
      {
        prop_key: "prop.channel_0",
        supportType: [1],
        switchStatus: ["on", 1],
        prop_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["channel_0", "on"],
              method: "toggle_ctrl_neutral",
              prop_value: "off",
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            { param: ["channel_0", "off"], method: "toggle_ctrl_neutral", prop_value: "on" },
          ],
          prop_key: "prop.channel_0",
        },
      ],
    },
    models: ["lumi.ctrl_ln1.v1", "lumi.switch.b1naus01", "lumi.ctrl_ln1.aq1"],
  },
  {
    props: [
      {
        prop_key: "prop.state",
        suportType: [1],
        switchStatus: [1, 2, 3],
        prop_name: { zh_CN: "电源", en: "Power" },
      },
      { supportType: [1], prop_key: "prop.mode", prop_name: { zh_CN: "模式选择", en: "Mode" } },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: 0,
              disable_status: [{ key: "prop.state", value: "1" }],
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: 1,
              disable_status: [{ key: "prop.state", value: "1" }],
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: 2,
              disable_status: [{ key: "prop.state", value: "1" }],
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: 3,
              disable_status: [{ key: "prop.state", value: "1" }],
            },
          ],
          prop_key: "prop.state",
        },
        {
          cardType: 12,
          operation: [
            {
              param: ["sports"],
              method: "set_mode",
              prop_value: "sports",
              button_name: { zh_CN: "运动", en: "Sports" },
              button_image: {
                selected: "popup_icon_strong_hig",
                unable: "popup_icon_strong_unable",
                normal: "popup_icon_strong_nor",
              },
              disable_status: [
                { key: "prop.state", value: "0" },
                { key: "prop.state", value: "1" },
              ],
            },
            {
              param: ["refresh"],
              method: "set_mode",
              prop_value: "refresh",
              button_name: { zh_CN: "舒缓", en: "Recover" },
              button_image: {
                selected: "popup_icon_naturalwind_hig",
                unable: "popup_icon_naturalwind_unable",
                normal: "popup_icon_naturalwind_nor",
              },
              disable_status: [
                { key: "prop.state", value: "0" },
                { key: "prop.state", value: "1" },
              ],
            },
            {
              param: ["sleep"],
              method: "set_mode",
              prop_value: "sleep",
              button_name: { zh_CN: "睡眠", en: "Sleep" },
              button_image: {
                selected: "popup_icon_sleep_hig",
                unable: "popup_icon_sleep_unable",
                normal: "popup_icon_sleep_nor",
              },
              disable_status: [
                { key: "prop.state", value: "0" },
                { key: "prop.state", value: "1" },
              ],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["rotai.massage.rt5850s"],
  },
  {
    props: [
      {
        prop_key: "prop.function_status",
        supportType: [1],
        switchStatus: ["running"],
        prop_name: { zh_CN: "开始取消", en: "" },
      },
      {
        prop_key: "prop.left_time",
        prop_unit: "min",
        supportType: [1, 2],
        prop_name: { zh_CN: "剩余时间", en: "remaining_time" },
        formmat: "%.0f",
      },
      { supportType: [1], prop_name: { zh_CN: "烹饪模式", en: "mode" }, prop_key: "prop.mode" },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          cardType: 2,
          operation: [
            {
              method: "set_cookstart",
              prop_value: "waiting",
              button_name: { zh_CN: "待机中", en: "waiting" },
              button_image: {
                selected: "btn_title_start",
                unable: "btn_title_start_disable",
                normal: "btn_title_pause",
              },
            },
            { button_name: { zh_CN: "烹饪中", en: "running" }, method: "set_cancel", prop_value: "running" },
          ],
          prop_key: "prop.function_status",
        },
        { supportGrid: 1, cardType: 7, prop_key: "prop.left_time" },
        {
          cardType: 3,
          operation: [
            {
              param: ["finecook"],
              method: "set_cookmenu",
              prop_value: "finecook",
              button_name: { zh_CN: "精煮", en: "finecook" },
              button_image: {
                selected: "popup_icon_finecook_hig",
                unable: "popup_icon_finecook_unable",
                normal: "popup_icon_finecook_nor",
              },
              disable_status: [{ key: "prop.function_status", value: "running" }],
            },
            {
              param: ["fastcook"],
              method: "set_cookmenu",
              prop_value: "fastcook",
              button_name: { zh_CN: "快煮", en: "fastcook" },
              button_image: {
                selected: "popup_icon_fastcook_hig",
                unable: "popup_icon_fastcook_disable",
                normal: "popup_icon_fastcook_nor",
              },
              disable_status: [{ key: "prop.function_status", value: "running" }],
            },
            {
              param: ["congee"],
              method: "set_cookmenu",
              prop_value: "congee",
              button_name: { zh_CN: "粥", en: "congee" },
              button_image: {
                selected: "popup_icon_cookcongee_hig",
                unable: "popup_icon_cookcongee_unable",
                normal: "popup_icon_cookcongee_nor",
              },
              disable_status: [{ key: "prop.function_status", value: "running" }],
            },
          ],
          prop_key: "prop.mode",
        },
      ],
    },
    models: ["chunmi.cooker.press2"],
  },
  {
    props: [{ supportType: [1], prop_key: "prop.state", prop_name: { zh_CN: "状态", en: "State" } }],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.state" }] },
    models: ["minij.washer.v3", "minij.washer.v6"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: [1],
        prop_name: { zh_CN: "电源", en: "Power" },
      },
      {
        prop_key: "prop.usetime",
        prop_unit: "min",
        supportType: [1],
        prop_name: { zh_CN: "剩余时间", en: "UseTime" },
        format: "%.0f",
      },
      {
        prop_key: "prop.start",
        supportType: [1],
        switchStatus: [2],
        prop_extra: [
          { value: 2, desc: { zh_CN: "启动", en: "Start" } },
          { value: 1, desc: { zh_CN: "暂停", en: "Pause" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: [1],
              method: "set_power",
              prop_value: 0,
              button_name: { zh_CN: "电源", en: "Power" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            { param: [0], method: "set_power", prop_value: 1 },
          ],
          prop_key: "prop.power",
        },
        { cardType: 7, prop_key: "prop.usetime" },
        {
          cardType: 2,
          operation: [
            {
              param: [1],
              method: "pause",
              prop_value: "1",
              button_name: { zh_CN: "暂停", en: "paused" },
              button_image: {
                selected: "btn_radio_pause",
                unable: "btn_radio_unable",
                normal: "btn_radio_play",
              },
              disable_status: [{ key: "prop.power", value: "0" }],
            },
            {
              param: [0],
              method: "pause",
              prop_value: "2",
              button_name: { zh_CN: "启动", en: "start" },
              button_image: {},
              disable_status: [{ key: "prop.power", value: "0" }],
            },
          ],
          prop_key: "prop.start",
        },
      ],
    },
    models: ["moyu.washer.s1hm"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "开关", en: "Power" },
      },
      { supportType: [1], prop_name: { zh_CN: "亮度调节", en: "Set bright" }, prop_key: "prop.bright" },
    ],
    cards: {
      layout_type: 1,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_image: { selected: "btn_single_on", unable: "btn_single_unable", normal: "btn_single_off" },
            },
            { param: ["off"], method: "set_power", prop_value: "on" },
          ],
          prop_key: "prop.power",
        },
        {
          prop_key: "prop.bright",
          cardType: 5,
          operation: [{ method: "set_bright", disable_status: [{ key: "prop.power", value: "off" }] }],
          param_range: { min: 1, max: 100 },
          small_image: "seekbar_thumb_light",
          param_type: [{ type: "JSONArray", index: "0" }, { type: "int" }],
        },
      ],
    },
    models: ["philips.light.hbulb"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.temperature",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "室内温度约", en: "Indoor temperature about" },
        ratio: 1,
        format: "%.0f",
      },
      {
        prop_key: "prop.target_temperature",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "目标温度", en: "Target temperature" },
        format: "%.0f",
      },
    ],
    cards: {
      card_items: [
        {
          supportGrid: 1,
          prop_key: "prop.power",
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_image: { selected: "", normal: "" },
            },
          ],
          cardType: 1,
        },
        { prop_key: "prop.temperature", cardType: 7 },
        {
          prop_key: "prop.target_temperature",
          cardType: 4,
          operation: [{ method: "set_target_temperature", disable_status: [{ key: "prop.power", value: "off" }] }],
          param_range: { min: 20, max: 32 },
          param_delta: 1,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "int" }],
        },
      ],
      layout_type: 3,
    },
    models: ["zhimi.heater.ma1"],
  },
  {
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: ["on"],
        prop_name: { zh_CN: "电源开关", en: "Power" },
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On" } },
          { value: "off", desc: { zh_CN: "关", en: "Off" } },
        ],
      },
      {
        prop_key: "prop.temperature",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "室内温度", en: "Indoor temperature" },
        ratio: 1,
        format: "%.0f",
      },
      {
        prop_key: "prop.target_temperature",
        prop_unit: "℃",
        supportType: [1],
        prop_name: { zh_CN: "目标温度", en: "Target temperature" },
        format: "%.0f",
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: ["on"],
              method: "set_power",
              prop_value: "off",
              button_name: { en: "Power", zh_HK: "開關", zh_CN: "开关", zh_TW: "開關" },
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: ["off"],
              method: "set_power",
              prop_value: "on",
              button_image: { selected: "", normal: "" },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 7, prop_key: "prop.temperature" },
        {
          prop_key: "prop.target_temperature",
          cardType: 4,
          operation: [{ method: "set_target_temperature", disable_status: [{ key: "prop.power", value: "off" }] }],
          param_range: { min: 16, max: 32 },
          param_delta: 1,
          param_type: [{ index: 0, type: "JSONArray" }, { type: "int" }],
        },
      ],
    },
    models: ["zhimi.heater.za1"],
  },
  {
    props: [
      {
        prop_name: { zh_CN: "设备状态", en: "State" },
        prop_extra: [
          { value: "off", desc: { zh_CN: "已关机", en: "Off" } },
          { value: "standby", desc: { zh_CN: "待机中", en: "Standby" } },
          { value: "run", desc: { zh_CN: "运行中", en: "Run" } },
          { value: "delay", desc: { zh_CN: "预约中", en: "Delay" } },
          { value: "pause", desc: { zh_CN: "已暂停", en: "Pause" } },
          { value: "fault", desc: { zh_CN: "出现故障", en: "Fault" } },
          { value: "eoc", desc: { zh_CN: "洗涤完成", en: "Finish" } },
        ],
        prop_key: "prop.state",
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.state" }] },
    models: ["minij.washer.v5", "minij.washer.v8"],
  },
  {
    props: [
      {
        prop_key: "prop.fire",
        prop_unit: "档",
        format: "%.0f",
        ratio: 1,
        prop_extra: [],
        prop_name: { en: "fire", zh_HK: "火力", zh_CN: "火力", zh_TW: "火力" },
      },
      {
        prop_key: "prop.left_time",
        prop_unit: "min",
        format: "%.0f",
        ratio: 1,
        prop_extra: [],
        prop_name: { en: "remaining_time", zh_HK: "剩余時間", zh_CN: "剩余时间", zh_TW: "剩余時間" },
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.fire" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.left_time" },
      ],
    },
    models: ["chunmi.ihcooker.tw1"],
  },
  {
    props: [
      {
        prop_name: { zh_CN: "设备状态", en: "status" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "待机", en: "Standby" } },
          { value: "1", desc: { zh_CN: "打印中", en: "Printing" } },
          { value: "2", desc: { zh_CN: "出错", en: "Error" } },
          { value: "3", desc: { zh_CN: "关机", en: "Powered Off" } },
          { value: "4", desc: { zh_CN: "睡眠", en: "Sleep Mode" } },
        ],
        prop_key: "prop.printer_status",
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.printer_status" }],
    },
    models: ["hannto.printer.honey"],
  },
  {
    props: [
      {
        prop_key: "prop.fire",
        prop_unit: "",
        format: "%.0f",
        ratio: 1,
        prop_extra: [],
        prop_name: {
          en: "Power",
          zh_TW: "火力",
          ru: "Мощность",
          zh_HK: "火力",
          zh_CN: "火力",
          es: "Potencia",
        },
      },
      {
        prop_key: "prop.left_time",
        format: "%.0f",
        prop_uint: "min",
        ratio: 1,
        prop_extra: [],
        prop_name: {
          en: "Time",
          zh_TW: "剩余時間",
          ru: "Время",
          zh_HK: "剩余時間",
          zh_CN: "剩余时间",
          es: "Tiempo",
        },
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.fire" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.left_time" },
      ],
    },
    models: ["chunmi.ihcooker.exp1"],
  },
  {
    props: [
      {
        prop_key: "prop.status",
        supportType: [1, 2],
        prop_name: {
          zh_HK: "當前狀態",
          zh_TW: "當前狀態",
          ru: "текущее состояние",
          es: "Estado actual",
          zh_CN: "当前状态",
          en: "current state",
          ja: "現在状態",
        },
        prop_extra: [
          {
            value: 1,
            desc: {
              zh_HK: "待機中",
              zh_TW: "待機中",
              ru: "Ожидание",
              es: "En espera",
              zh_CN: "待机中",
              en: "Standby",
              ja: "待機中",
            },
          },
          {
            value: 2,
            desc: {
              zh_HK: "烹飪中",
              zh_TW: "烹飪中",
              ru: "Приготовление",
              es: "Cocinando",
              zh_CN: "烹饪中",
              en: "Cooking",
              ja: "料理中",
            },
          },
          {
            value: 3,
            desc: {
              zh_HK: "保溫中",
              zh_TW: "保溫中",
              ru: "Поддержание тепла",
              es: "Mantener caliente",
              zh_CN: "保温中",
              en: "Keep warm",
              ja: "保温中",
            },
          },
          {
            value: 4,
            desc: {
              zh_HK: "預約中",
              zh_TW: "預約中",
              ru: "Таймер",
              es: "Temporizador",
              zh_CN: "预约中",
              en: "Appointment",
              ja: "予約中",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.status" }] },
    models: ["chunmi.cooker.k1pro1", "chunmi.cooker.eh1"],
  },
  {
    props: [
      {
        prop_key: "prop.work_status",
        supportType: [1, 2],
        prop_name: {
          zh_HK: "當前狀態",
          zh_TW: "當前狀態",
          ru: "текущее состояние",
          es: "Estado actual",
          zh_CN: "当前状态",
          en: "current state",
          ja: "現在状態",
        },
        prop_extra: [
          {
            value: "standby",
            desc: {
              zh_HK: "待機中",
              zh_TW: "待機中",
              ru: "Ожидание",
              es: "En espera",
              zh_CN: "待机中",
              en: "Standby",
              ja: "待機中",
            },
          },
          {
            value: "cooking-delicacy",
            desc: {
              zh_HK: "烹飪中",
              zh_TW: "烹飪中",
              ru: "Приготовление",
              es: "Cocinando",
              zh_CN: "烹饪中",
              en: "Cooking",
              ja: "料理中",
            },
          },
          {
            value: "cooking-quickly",
            desc: {
              zh_HK: "烹飪中",
              zh_TW: "烹飪中",
              ru: "Приготовление",
              es: "Cocinando",
              zh_CN: "烹饪中",
              en: "Cooking",
              ja: "料理中",
            },
          },
          {
            value: "cooking-porridge",
            desc: {
              zh_HK: "烹飪中",
              zh_TW: "烹飪中",
              ru: "Приготовление",
              es: "Cocinando",
              zh_CN: "烹饪中",
              en: "Cooking",
              ja: "料理中",
            },
          },
          {
            value: "cooking-selected",
            desc: {
              zh_HK: "烹飪中",
              zh_TW: "烹飪中",
              ru: "Приготовление",
              es: "Cocinando",
              zh_CN: "烹饪中",
              en: "Cooking",
              ja: "料理中",
            },
          },
          {
            value: "keepwarm",
            desc: {
              zh_HK: "保溫中",
              zh_TW: "保溫中",
              ru: "Поддержание тепла",
              es: "Mantener caliente",
              zh_CN: "保温中",
              en: "Keep warm",
              ja: "保温中",
            },
          },
          {
            value: "preorder",
            desc: {
              zh_HK: "預約中",
              zh_TW: "預約中",
              ru: "Таймер",
              es: "Temporizador",
              zh_CN: "预约中",
              en: "Appointment",
              ja: "予約中",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.work_status" }] },
    models: ["chunmi.cooker.najpn1", "chunmi.cooker.naeg1"],
  },
  {
    props: [
      { switchStatus: [true], prop_key: "prop.power" },
      {
        prop_key: "prop.pm25",
        format: "%.0f",
        prop_name: { en: "PM2.5", zh_HK: "PM2.5", zh_CN: "PM2.5", zh_TW: "PM2.5" },
      },
      {
        prop_key: "prop.co2",
        format: "%.0f",
        prop_name: { en: "CO2", zh_HK: "CO2", zh_CN: "CO2", zh_TW: "CO2" },
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          operation: [
            {
              param: [true],
              method: "set_power",
              prop_value: false,
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
            {
              param: [false],
              method: "set_power",
              prop_value: true,
              button_image: {
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
                normal: "title_btn_power_off",
              },
            },
          ],
          prop_key: "prop.power",
        },
        { cardType: 7, prop_key: "prop.co2" },
        { cardType: 7, prop_key: "prop.pm25" },
      ],
    },
    models: ["dmaker.airfresh.t2017"],
  },
  {
    props: [
      {
        prop_key: "prop.run_status",
        supportType: [1, 2],
        prop_name: { zh_CN: "当前状态", en: "current state" },
        prop_extra: [
          { value: 1, desc: { zh_CN: "升温中", en: "Heating up" } },
          { value: 2, desc: { zh_CN: "升压中", en: "Increasing pressure" } },
          { value: 3, desc: { zh_CN: "保压中", en: "Maintain pressure" } },
          { value: 4, desc: { zh_CN: "泄压中", en: "Release pressure" } },
          { value: 5, desc: { zh_CN: "预约中", en: "Timer" } },
          { value: 6, desc: { zh_CN: "预约暂停", en: "Pause" } },
          { value: 7, desc: { zh_CN: "烹饪暂停", en: "Pause" } },
          { value: 8, desc: { zh_CN: "保温暂停", en: "Pause" } },
          { value: 9, desc: { zh_CN: "待烹饪", en: "Ready" } },
          { value: 10, desc: { zh_CN: "烹饪中", en: "Cooking" } },
          { value: 11, desc: { zh_CN: "保温中", en: "Keep warm" } },
          { value: 12, desc: { zh_CN: "烹饪完成", en: "Cooking completed" } },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.run_status" }] },
    models: ["chunmi.pre_cooker.eh1"],
  },
  {
    props: [
      {
        prop_key: "prop.work_status",
        prop_unit: "",
        format: "%.0f",
        prop_extra: [
          { value: "0", desc: { zh_CN: "待机中", en: "Idle" } },
          { value: "1", desc: { zh_CN: "预约中", en: "Setting timer" } },
          { value: "2", desc: { zh_CN: "烹饪中", en: "Cooking" } },
          { value: "3", desc: { zh_CN: "烹饪中", en: "Cooking" } },
          { value: "4", desc: { zh_CN: "保温中", en: "Keeping hot" } },
          { value: "5", desc: { zh_CN: "烹饪完成", en: "Finished" } },
        ],
        ratio: 1,
        prop_name: { zh_CN: "", en: "" },
      },
    ],
    cards: { layout_type: 0, card_items: [{ cardType: 8, prop_key: "prop.work_status" }] },
    models: ["viomi.health_pot.v1"],
  },
  {
    cards: { card_items: [{ cardType: 8, prop_key: "prop.status_code" }], layout_type: 0 },
    models: ["hannto.printer.anise"],
    props: [
      {
        prop_extra: [
          { desc: { en: "Printer Initialization", zh_CN: "打印机初始化" }, value: 0 },
          { desc: { en: "Standby", zh_CN: "打印机待机" }, value: 10000000 },
          { desc: { en: "Standby", zh_CN: "打印机待机" }, value: 20000000 },
          { desc: { en: "Standby", zh_CN: "打印机待机" }, value: 20900000 },
          { desc: { en: "Standby", zh_CN: "打印机待机" }, value: 50000000 },
          { desc: { en: "Standby", zh_CN: "打印机待机" }, value: 50900000 },
          { desc: { en: "Initializing CISS", zh_CN: "连供系统初始化" }, value: 11000000 },
          { desc: { en: "Sleep Mode", zh_CN: "打印机休眠" }, value: 30000000 },
          { desc: { en: "Printing", zh_CN: "打印中" }, value: 40400000 },
          { desc: { en: "Printing", zh_CN: "打印中" }, value: 41100000 },
          { desc: { en: "Maintenance", zh_CN: "系统维护" }, value: 40500000 },
          { desc: { en: "Firmware Upgrading", zh_CN: "固件升级中" }, value: 40600000 },
          { desc: { en: "Reset to Factory Default", zh_CN: "正在恢复出厂设置" }, value: 40800000 },
          { desc: { en: "Powered Off", zh_CN: "打印机关机" }, value: 60000000 },
          { desc: { en: "Pen Door Opened", zh_CN: "墨仓门开启" }, value: 70005002 },
          { desc: { en: "Carrier Locked", zh_CN: "打印头架锁定中" }, value: 70005103 },
          { desc: { en: "Carrier Locked", zh_CN: "打印头架锁定中" }, value: 70005102 },
          { desc: { en: "Input Tray Error", zh_CN: "进纸托盘错误" }, value: 70005101 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70004001 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003002 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003003 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003004 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003005 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003006 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70006106 },
          { desc: { en: "Print Head Missing", zh_CN: "打印头缺失" }, value: 70002007 },
          { desc: { en: "Print Head Missing", zh_CN: "打印头缺失" }, value: 70002008 },
          { desc: { en: "Print Head Missing", zh_CN: "打印头缺失" }, value: 70002009 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002013 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002014 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002015 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002006 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002010 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002011 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002012 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002016 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002017 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002018 },
          { desc: { en: "Print Head Error", zh_CN: "打印头错误" }, value: 70002019 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002101 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002102 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002103 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002104 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002105 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002106 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002107 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002108 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002109 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002110 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002111 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002112 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002113 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002114 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002115 },
          { desc: { en: "Low on Ink", zh_CN: "墨水量低" }, value: 70002301 },
          { desc: { en: "Memory Error", zh_CN: "打印机内存故障" }, value: 70005201 },
          { desc: { en: "Memory Error", zh_CN: "打印机内存故障" }, value: 70005202 },
          { desc: { en: "Printer Error", zh_CN: "打印机故障" }, value: 70005301 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70003007 },
          { desc: { en: "Paper Error", zh_CN: "纸张错误" }, value: 70004002 },
        ],
        prop_key: "prop.status_code",
        prop_name: { en: "Current Status", zh_CN: "当前状态" },
      },
    ],
  },
  {
    models: [
      "ikea.light.led1649c5",
      "ikea.light.led1536g5",
      "ikea.light.led1623g12",
      "ikea.light.led1546g12",
      "ikea.light.led1545g12",
      "ikea.light.led1650r5",
      "ikea.light.led1537r6",
    ],
    props: [
      {
        prop_name: { zh_CN: "电源", en: "Power", zh_TW: "電源", zh_HK: "電源" },
        prop_key: "prop.power_status",
        supportType: [1],
        prop_extra: [
          { value: "on", desc: { zh_CN: "开", en: "On", zh_TW: "開", zh_HK: "開" } },
          { value: "off", desc: { zh_CN: "关", en: "Off", zh_TW: "關", zh_HK: "關" } },
        ],
        switchStatus: ["on"],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          prop_key: "prop.power_status",
          operation: [
            {
              button_image: {
                normal: "btn_single_off",
                selected: "btn_single_on",
                unable: "btn_single_unable",
              },
              button_name: { zh_CN: "电源", en: "Power", zh_TW: "電源", zh_HK: "電源" },
              prop_value: "off",
              method: "set_power",
              param: ["on"],
            },
            {
              button_image: { normal: "", selected: "" },
              button_name: { zh_CN: "电源", en: "Power", zh_TW: "電源", zh_HK: "電源" },
              prop_value: "on",
              method: "set_power",
              param: ["off"],
            },
          ],
        },
      ],
    },
  },
  {
    models: ["viomi.juicer.v1"],
    props: [
      {
        prop_key: "prop.work_status",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Status", zh_CN: "工作状态" },
        prop_extra: [
          { value: "0", desc: { en: "Idle", zh_CN: "空闲中" } },
          { value: "1", desc: { en: "Reserving", zh_CN: "预约中" } },
          { value: "2", desc: { en: "Preparing", zh_CN: "料理中" } },
          { value: "3", desc: { en: "Preparing", zh_CN: "料理中" } },
          { value: "4", desc: { en: "Heat keeping", zh_CN: "保温中" } },
          { value: "5", desc: { en: "Idle", zh_CN: "空闲中" } },
          { value: "6", desc: { en: "Completed", zh_CN: "料理完成" } },
        ],
      },
      {
        prop_key: "prop.mode",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Mode", zh_CN: "料理模式" },
        prop_extra: [
          { value: "1", desc: { en: "Milkshake", zh_CN: "奶昔" } },
          { value: "2", desc: { en: "Shaved ice", zh_CN: "沙冰" } },
          { value: "3", desc: { en: "Sauce", zh_CN: "酱料" } },
          { value: "4", desc: { en: "Fruit & vegetable juice", zh_CN: "果蔬汁" } },
          { value: "5", desc: { en: "Corn juice", zh_CN: "玉米汁" } },
          { value: "6", desc: { en: "Congee", zh_CN: "粥品" } },
          { value: "7", desc: { en: "Soy milk", zh_CN: "豆浆" } },
          { value: "8", desc: { en: "Thick soup", zh_CN: "浓汤" } },
          { value: "9", desc: { en: "Rice paste", zh_CN: "米糊" } },
          { value: "10", desc: { en: "Manual", zh_CN: "点动" } },
          { value: "11", desc: { en: "Custom", zh_CN: "手动" } },
        ],
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        { cardType: 8, prop_key: "prop.work_status" },
        { cardType: 8, prop_key: "prop.mode" },
      ],
    },
  },
  {
    models: ["viomi.hood.a1", "viomi.hood.a4", "viomi.hood.a9", "viomi.hood.c1", "viomi.hood.h1"],
    props: [
      {
        prop_key: "prop.power_state",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Power", zh_CN: "电源" },
        switchStatus: ["2"],
        prop_extra: [
          { value: "0", desc: { en: "Off", zh_CN: "已关机" } },
          { value: "1", desc: { en: "Delay to shut down", zh_CN: "延迟关机中" } },
          { value: "2", desc: { en: "On", zh_CN: "工作中" } },
          { value: "3", desc: { en: "Cleaning", zh_CN: "清洗" } },
          { value: "4", desc: { desc: { en: "Clean reset", zh_CN: "清洗复位" } } },
        ],
      },
      {
        prop_key: "prop.wind_state",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Mode", zh_CN: "模式" },
        prop_extra: [
          { value: "1", desc: { en: "Low", zh_CN: "低挡" } },
          { value: "16", desc: { en: "Middle", zh_CN: "高挡" } },
          { value: "4", desc: { en: "High", zh_CN: "爆炒" } },
        ],
      },
      {
        prop_key: "prop.light_state",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Light", zh_CN: "照明" },
        switchStatus: ["1"],
        prop_extra: [
          { value: "0", desc: { en: "Off", zh_CN: "关闭" } },
          { value: "1", desc: { en: "On", zh_CN: "打开" } },
        ],
      },
    ],
    cards: {
      layout_type: 3,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          prop_key: "prop.power_state",
          operation: [
            {
              button_image: {
                normal: "title_btn_power_off",
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
              },
              prop_value: "0",
              method: "set_power",
              param: ["2"],
            },
            {
              button_image: {
                normal: "title_btn_power_off",
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
              },
              prop_value: "1",
              method: "set_power",
              param: ["2"],
            },
            {
              button_image: {
                normal: "title_btn_power_on",
                selected: "title_btn_power_off",
                unable: "title_btn_power_unable",
              },
              prop_value: "2",
              method: "set_power",
              param: ["0"],
            },
            {
              button_image: {
                normal: "title_btn_power_off",
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
              },
              prop_value: "3",
              method: "set_power",
              param: ["2"],
            },
            {
              button_image: {
                normal: "title_btn_power_off",
                selected: "title_btn_power_on",
                unable: "title_btn_power_unable",
              },
              prop_value: "4",
              method: "set_power",
              param: ["2"],
            },
          ],
        },
        { cardType: 8, prop_key: "prop.power_state" },
        {
          cardType: 3,
          prop_key: "prop.wind_state",
          operation: [
            {
              button_name: { en: "Low", zh_CN: "低挡" },
              button_image: { normal: "btn_auto_off", selected: "btn_auto_on", unable: "btn_auto_unable" },
              prop_value: "1",
              method: "set_wind",
              param: ["1"],
              disable_status: [{ key: "prop.power_state", value: "0" }],
            },
            {
              button_name: { en: "Middle", zh_CN: "高挡", zh_TW: "高挡", zh_HK: "高挡" },
              button_image: { normal: "btn_sleep_off", selected: "btn_sleep_on", unable: "btn_sleep_unable" },
              prop_value: "4",
              method: "set_wind",
              param: ["4"],
              disable_status: [{ key: "prop.power_state", value: "0" }],
            },
            {
              button_name: { en: "High", zh_CN: "爆炒", zh_TW: "爆炒", zh_HK: "爆炒" },
              button_image: {
                normal: "popup_icon_love_nor",
                selected: "popup_icon_love_hig",
                unable: "popup_icon_love_unable",
              },
              prop_value: "16",
              method: "set_wind",
              param: ["16"],
              disable_status: [{ key: "prop.power_state", value: "0" }],
            },
          ],
        },
      ],
    },
  },
  {
    models: ["viomi.waterheater.u1", "viomi.waterheater.u4", "viomi.waterheater.u6"],
    props: [
      {
        prop_key: "prop.targetTemp",
        prop_name: { zh_CN: "设置温度", en: "Heating temp." },
        ratio: 1,
        format: "%.0f",
        prop_unit: "℃",
        prop_extra: [],
      },
      {
        prop_key: "prop.washStatus",
        prop_name: { zh_CN: "开关状态", en: "Status" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "关闭", en: "Power off" } },
          { value: "1", desc: { zh_CN: "开启", en: "Power on" } },
          { value: "2", desc: { zh_CN: "洗浴中", en: "In the bath" } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { cardType: 7, prop_key: "prop.targetTemp" },
        { cardType: 8, prop_key: "prop.washStatus" },
      ],
    },
  },
  {
    models: ["viomi.waterheater.e1", "viomi.waterheater.e4"],
    props: [
      {
        prop_key: "prop.modeType",
        prop_name: { zh_CN: "设备模式", en: "Device mode" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "日常温水", en: "Thermostatic" } },
          { value: "1", desc: { zh_CN: "速热洗浴", en: "Heating" } },
          { value: "2", desc: { zh_CN: "预约", en: "Booking" } },
        ],
      },
      {
        prop_key: "prop.waterTemp",
        prop_name: { zh_CN: "当前水温", en: "Water temp." },
        ratio: 1,
        format: "%.0f",
        prop_unit: "℃",
        prop_extra: [],
      },
      {
        prop_key: "prop.targetTemp",
        prop_name: { zh_CN: "目标水温", en: "Target temp." },
        ratio: 1,
        format: "%.0f",
        prop_unit: "℃",
        prop_extra: [],
      },
    ],
    cards: {
      layout_type: 4,
      card_items: [
        { cardType: 8, prop_key: "prop.modeType" },
        { cardType: 7, prop_key: "prop.waterTemp" },
        { cardType: 7, prop_key: "prop.targetTemp" },
      ],
    },
  },
  {
    models: ["viomi.juicer.v2"],
    props: [
      {
        prop_key: "prop.work_status",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Status", zh_CN: "工作状态" },
        prop_extra: [
          { value: "0", desc: { en: "Idle", zh_CN: "空闲中" } },
          { value: "1", desc: { en: "Reserving", zh_CN: "预约中" } },
          { value: "2", desc: { en: "Cooking", zh_CN: "料理中" } },
          { value: "3", desc: { en: "Cooking", zh_CN: "料理中" } },
          { value: "4", desc: { en: "Heat keeping", zh_CN: "保温中" } },
          { value: "5", desc: { en: "Idle", zh_CN: "空闲中" } },
          { value: "6", desc: { en: "Completed", zh_CN: "料理完成" } },
        ],
      },
      {
        prop_key: "prop.mode",
        format: "%.0f",
        prop_unit: "",
        ratio: 1,
        prop_name: { en: "Mode", zh_CN: "料理模式" },
        prop_extra: [
          { value: "1", desc: { en: "Soybean milk", zh_CN: "浓豆浆" } },
          { value: "2", desc: { en: "Baby’s rice paste", zh_CN: "婴儿糊" } },
          { value: "3", desc: { en: "Thick soup", zh_CN: "浓汤" } },
          { value: "4", desc: { en: "Juice", zh_CN: "果蔬汁" } },
          { value: "5", desc: { en: "Smoothie", zh_CN: "冰沙" } },
          { value: "6", desc: { en: "Corn juice", zh_CN: "玉米汁" } },
          { value: "7", desc: { en: "Heating", zh_CN: "加热" } },
          { value: "8", desc: { en: "Manual drive", zh_CN: "手动" } },
          { value: "9", desc: { en: "Borscht", zh_CN: "罗宋汤" } },
          { value: "10", desc: { en: "Congee", zh_CN: "绵粥" } },
          { value: "11", desc: { en: "Sesame paste", zh_CN: "芝麻糊" } },
          { value: "12", desc: { en: "Heat keeping", zh_CN: "保温" } },
          { value: "13", desc: { en: "Motor drive", zh_CN: "点动" } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { cardType: 8, prop_key: "prop.work_status" },
        { cardType: 8, prop_key: "prop.mode" },
      ],
    },
  },
  {
    models: ["lumi.sensor_motion.v1", "lumi.sensor_motion.v2", "lumi.sensor_motion.aq2"],
    props: [
      {
        prop_key: "event.motion",
        show_type: "date",
        prop_name: {
          zh_HK: "有人移動",
          zh_TW: "有人移動",
          en: "Someone passes by",
          zh_CN: "有人移动",
          es: "Alguien pasa por",
          ru: "Кто-то проходит мимо",
          it: "è passato qualcuno",
          fr: "Quelqu’un passe à proximité",
          de: "Jemand geht vorbei an",
          pl: "Ktoś przechodzi",
        },
        prop_status_name: {
          zh_HK: "有人移動",
          zh_TW: "有人移動",
          en: "Someone passes by",
          zh_CN: "有人移动",
          es: "Alguien pasa por",
          ru: "Кто-то проходит мимо",
          it: "è passato qualcuno",
          fr: "Quelqu’un passe à proximité",
          de: "Jemand geht vorbei an",
          pl: "Ktoś przechodzi",
        },
        supportType: [1, 2],
        prop_value_type: [{ key: "timestamp", type: "JSONObject" }, { type: "long" }],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 10, prop_key: "event.motion" }] },
  },
  {
    models: ["lumi.sensor_magnet.v1", "lumi.sensor_magnet.v2", "lumi.sensor_magnet.aq2"],
    props: [
      {
        prop_key: "prop.open",
        prop_name: {
          zh_HK: "門窗",
          zh_TW: "門窗",
          en: "Door/window",
          zh_CN: "门窗",
          es: "Puerta/ventana",
          ru: "Дверь/окно",
          it: "Porta/finestra",
          fr: "Porte/fenêtre",
          de: "Tür-/Fenster",
          pl: "Drzwi/okno",
        },
        supportType: [1, 2],
        prop_extra: [
          {
            value: "1",
            desc: {
              zh_HK: "打開",
              zh_TW: "打開",
              en: "Open",
              zh_CN: "打开",
              es: "Abierto",
              ru: "Открыто",
              it: "Aperto",
              fr: "Ouvrir",
              de: "Öffnen",
              pl: "Otwarty",
            },
          },
          {
            value: "0",
            desc: {
              zh_HK: "關閉",
              zh_TW: "關閉",
              en: "Close",
              zh_CN: "关闭",
              es: "Cerrar",
              ru: "Близко",
              it: "Vicino",
              fr: "Fermer",
              de: "Schließen",
              pl: "Blisko",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.open" }] },
  },
  {
    models: ["lumi.gateway.v2", "lumi.gateway.v1", "lumi.gateway.mitw01", "lumi.gateway.mieu01", "lumi.gateway.mihk01"],
    props: [
      {
        prop_name: {
          zh_HK: "夜燈",
          zh_TW: "夜燈",
          en: "Night light",
          zh_CN: "夜灯",
          es: "Luz de noche",
          ru: "Ночной свет",
          it: "Luce notturna",
          fr: "Lumière nocturne",
          de: "Nachtlicht",
          pl: "Oświetlenie nocne",
        },
        prop_key: "prop.light",
        switchStatus: ["on"],
      },
      {
        prop_name: {
          zh_HK: "警戒",
          zh_TW: "警戒",
          en: "Alert",
          zh_CN: "警戒",
          es: "Alerta",
          ru: "Оповещение",
          it: "Avviso",
          fr: "Alerte",
          de: "Alarm",
          pl: "Alarm",
        },
        prop_key: "prop.arming",
        switchStatus: ["on", "oning", "alarming"],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        {
          cardType: 1,
          prop_key: "prop.light",
          operation: [
            {
              button_image: {
                normal: "btn_gatewaylight_off",
                selected: "btn_gatewaylight_on",
                unable: "btn_gatewaylight_unable",
              },
              button_name: {
                zh_CN: "夜灯",
                en: "Night light",
                zh_TW: "夜燈",
                zh_HK: "夜燈",
                es: "Luz de noche",
                ru: "Ночной свет",
                it: "Luce notturna",
                fr: "Lumière nocturne",
                de: "Nachtlicht",
                pl: "Oświetlenie nocne",
              },
              prop_value: "off",
              method: "toggle_light",
              param: ["on"],
            },
            {
              button_image: {
                normal: "btn_gatewaylight_off",
                selected: "btn_gatewaylight_on",
                unalbe: "btn_gatewaylight_unable",
              },
              button_name: {
                zh_CN: "夜灯",
                en: "Night light",
                zh_TW: "夜燈",
                zh_HK: "夜燈",
                es: "Luz de noche",
                ru: "Ночной свет",
                it: "Luce notturna",
                fr: "Lumière nocturne",
                de: "Nachtlicht",
                pl: "Oświetlenie nocne",
              },
              prop_value: "on",
              method: "toggle_light",
              param: ["off"],
            },
          ],
        },
        {
          supportGrid: 1,
          cardType: 1,
          prop_key: "prop.arming",
          operation: [
            {
              button_image: { normal: "btn_alert_off", selected: "btn_alert_on", unable: "btn_alert_unable" },
              button_name: {
                zh_CN: "警戒",
                en: "Alert",
                zh_TW: "警戒",
                zh_HK: "警戒",
                es: "Alerta",
                ru: "Оповещение",
                it: "Avviso",
                fr: "Alerte",
                de: "Alarm",
                pl: "Alarm",
              },
              prop_value: "off",
              method: "set_arming",
              param: ["on"],
            },
            {
              button_image: { normal: "", selected: "" },
              button_name: {
                zh_CN: "警戒",
                en: "Alert",
                zh_TW: "警戒",
                zh_HK: "警戒",
                es: "Alerta",
                ru: "Оповещение",
                it: "Avviso",
                fr: "Alerte",
                de: "Alarm",
                pl: "Alarm",
              },
              prop_value: "on",
              method: "set_arming",
              param: ["off"],
            },
            {
              button_image: { normal: "", selected: "" },
              button_name: {
                zh_CN: "警戒",
                en: "Alert",
                zh_TW: "警戒",
                zh_HK: "警戒",
                es: "Alerta",
                ru: "Оповещение",
                it: "Avviso",
                fr: "Alerte",
                de: "Alarm",
                pl: "Alarm",
              },
              prop_value: "alarming",
              method: "set_arming",
              param: ["off"],
            },
            {
              button_image: { normal: "", selected: "" },
              button_name: {
                zh_CN: "警戒",
                en: "Alert",
                zh_TW: "警戒",
                zh_HK: "警戒",
                es: "Alerta",
                ru: "Оповещение",
                it: "Avviso",
                fr: "Alerte",
                de: "Alarm",
                pl: "Alarm",
              },
              prop_value: "oning",
              method: "set_arming",
              param: ["off"],
            },
          ],
        },
      ],
    },
  },
  {
    models: ["miaomiaoce.sensor_ht.t1"],
    props: [
      {
        prop_key: "prop.4100",
        prop_name: { en: "temperature", zh_CN: "温度", zh_TW: "溫度", zh_HK: "溫度" },
        ratio: 0.1,
        format: "%.1f",
        prop_unit: "℃",
        supportType: [1, 2],
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 0, max: 22 } },
          { text_color: "#FFE0AC15", param_range: { min: 23, max: 40 } },
        ],
      },
      {
        prop_key: "prop.4102",
        prop_name: { en: "humidity", zh_CN: "湿度", zh_TW: "濕度", zh_HK: "濕度" },
        ratio: 0.1,
        format: "%.0f",
        prop_unit: "%",
        supportType: [1, 2],
        prop_extra: [
          { text_color: "#FF2DD1E2", param_range: { min: 51, max: 99 } },
          { text_color: "#FFE0AC15", param_range: { min: 0, max: 50 } },
        ],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.4100" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.4102" },
      ],
    },
  },
  {
    models: ["chunmi.cooker.normal2", "chunmi.cooker.normal1"],
    props: [
      {
        prop_name: {
          zh_CN: "当前状态",
          en: "current state",
          zh_TW: "當前狀態",
          zh_HK: "當前狀態",
          es: "Estado actual",
          ru: "текущее состояние",
          ja: "現在状態",
        },
        prop_key: "prop.work_status",
        supportType: [1, 2],
        prop_extra: [
          {
            value: "standby",
            desc: {
              zh_CN: "待机中",
              en: "Standby",
              zh_TW: "待機中",
              zh_HK: "待機中",
              es: "En espera",
              ru: "Ожидание",
              ja: "待機中",
            },
          },
          {
            value: "cooking-delicacy",
            desc: {
              zh_CN: "烹饪中",
              en: "Cooking",
              zh_TW: "烹飪中",
              zh_HK: "烹飪中",
              es: "Cocinando",
              ru: "Приготовление",
              ja: "料理中",
            },
          },
          {
            value: "cooking-quickly",
            desc: {
              zh_CN: "烹饪中",
              en: "Cooking",
              zh_TW: "烹飪中",
              zh_HK: "烹飪中",
              es: "Cocinando",
              ru: "Приготовление",
              ja: "料理中",
            },
          },
          {
            value: "cooking-porridge",
            desc: {
              zh_CN: "烹饪中",
              en: "Cooking",
              zh_TW: "烹飪中",
              zh_HK: "烹飪中",
              es: "Cocinando",
              ru: "Приготовление",
              ja: "料理中",
            },
          },
          {
            value: "cooking-selected",
            desc: {
              zh_CN: "烹饪中",
              en: "Cooking",
              zh_TW: "烹飪中",
              zh_HK: "烹飪中",
              es: "Cocinando",
              ru: "Приготовление",
              ja: "料理中",
            },
          },
          {
            value: "keepwarm",
            desc: {
              zh_CN: "保温中",
              en: "Keep warm",
              zh_TW: "保溫中",
              zh_HK: "保溫中",
              es: "Mantener caliente",
              ru: "Поддержание тепла",
              ja: "保温中",
            },
          },
          {
            value: "preorder",
            desc: {
              zh_CN: "预约中",
              en: "Appointment",
              zh_TW: "預約中",
              zh_HK: "預約中",
              es: "Temporizador",
              ru: "Таймер",
              ja: "予約中",
            },
          },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ supportGrid: 1, cardType: 8, prop_key: "prop.work_status" }] },
  },
  {
    models: ["chunmi.ihcooker.tkpro1"],
    props: [
      {
        prop_name: {
          zh_CN: "火力",
          en: "Power",
          zh_TW: "火力",
          zh_HK: "火力",
          es: "Potencia",
          ru: "Мощность",
        },
        prop_key: "prop.fire",
        ratio: 1,
        format: "%.0f",
        prop_unit: "",
        prop_extra: [],
      },
      {
        prop_name: {
          zh_CN: "剩余时间",
          en: "Time",
          zh_TW: "剩余時間",
          zh_HK: "剩余時間",
          es: "Tiempo",
          ru: "Время",
        },
        prop_key: "prop.left_time",
        ratio: 1,
        format: "%.0f",
        prop_unit: "min",
        prop_extra: [],
      },
    ],
    cards: {
      layout_type: 2,
      card_items: [
        { supportGrid: 1, cardType: 7, prop_key: "prop.fire" },
        { supportGrid: 1, cardType: 7, prop_key: "prop.left_time" },
      ],
    },
  },
  {
    models: ["dmaker.fan.p5"],
    props: [
      {
        prop_key: "prop.power",
        supportType: [1],
        switchStatus: [true],
        prop_name: { zh_CN: "开关", en: "Power", zh_TW: "開關", zh_HK: "開關" },
      },
    ],
    cards: {
      layout_type: 0,
      card_items: [
        {
          supportGrid: 1,
          cardType: 1,
          prop_key: "prop.power",
          operation: [
            {
              button_image: {
                normal: "btn_single_off",
                selected: "btn_single_on",
                unable: "btn_single_unable",
              },
              button_name: { zh_CN: "开关", en: "Power", zh_TW: "開關", zh_HK: "開關" },
              prop_value: false,
              method: "s_power",
              param: [true],
            },
            {
              button_image: {
                normal: "btn_single_off",
                selected: "btn_single_on",
                unable: "btn_single_unable",
              },
              button_name: { zh_CN: "开关", en: "Power", zh_TW: "開關", zh_HK: "開關" },
              prop_value: true,
              method: "s_power",
              param: [false],
            },
          ],
        },
      ],
    },
  },
  {
    models: ["hannto.printer.honey"],
    props: [
      {
        prop_key: "prop.printer_status",
        prop_name: { zh_CN: "设备状态", en: "status" },
        prop_extra: [
          { value: "0", desc: { zh_CN: "待机", en: "Standby" } },
          { value: "1", desc: { zh_CN: "打印中", en: "Printing" } },
          { value: "2", desc: { zh_CN: "出错", en: "Error" } },
          { value: "3", desc: { zh_CN: "关机", en: "Powered Off" } },
          { value: "4", desc: { zh_CN: "睡眠", en: "Sleep Mode" } },
          { value: "5", desc: { zh_CN: "升级中", en: "Upgrading" } },
        ],
      },
    ],
    cards: { layout_type: 0, card_items: [{ cardType: 8, prop_key: "prop.printer_status" }] },
  },
];
module.exports = configDes;
