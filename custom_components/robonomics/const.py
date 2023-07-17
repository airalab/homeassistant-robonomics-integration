"""Constants for the Robonomics Control integration."""

from homeassistant.const import Platform

DOMAIN = "robonomics"
PLATFORMS = [Platform.BUTTON]

CREATE_BACKUP_SERVICE = "save_backup_to_robonomics"
RESTORE_BACKUP_SERVICE = "restore_from_robonomics_backup"
SAVE_VIDEO_SERVICE = "save_video_to_robonomics"

CONF_ADMIN_SEED = "admin_seed_secret"
CONF_SUB_OWNER_ADDRESS = "sub_owner_address"
CONF_PINATA_PUB = "pinata_pub"
CONF_PINATA_SECRET = "pinata_secret"
CONF_SENDING_TIMEOUT = "sending_timeout"
CONF_ENERGY_SENSORS = "energy_sensors"
CONF_IPFS_GATEWAY = "user_ipfs_gateway"
CONF_IPFS_GATEWAY_AUTH = "user_ipfs_gateway_auth"
CONF_IPFS_GATEWAY_PORT = "user_ipfs_gateway_port"
CONF_WARN_DATA_SENDING = "warn_data_sending"
CONF_WARN_ACCOUNT_MANAGMENT = "warn_account_managment"
CONF_PINATA_USE = "pinata_use"
CONF_CUSTOM_GATEWAY_USE = "custom_gateway_use"

IPFS_GATEWAY = "https://ipfs.io/ipfs/"
MORALIS_GATEWAY = "https://gateway.moralisipfs.com/ipfs/"
PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

ROBONOMICS_WSS = [
    "wss://kusama.rpc.robonomics.network/",
    "wss://robonomics.leemo.me/",
    "wss://robonomics.api.onfinality.io/public-ws/",
    "wss://robonomics.0xsamsara.com/"
]

SENDING_TIMEOUT = "sending_timeout"
ROBONOMICS = "robonomics"
PINATA = "pinata"
IPFS_API = "ipfs_api"
HANDLE_TIME_CHANGE = "hadle_time_change"
TIME_CHANGE_UNSUB = "time_change_unsub"
HANDLE_IPFS_REQUEST = "handle_ipfs_request"

DATA_PATH = ".ha_robonomics_data"
DATA_BACKUP_ENCRYPTED_NAME = "backup_remote_encrypted"
IPFS_HASH_CONFIG = "ipfs_hash_config"
IPFS_TELEMETRY_PATH = "/ha_robonomics_telemetry"
IPFS_BACKUP_PATH = "/ha_robonomics_backup"
IPFS_CONFIG_PATH = "/ha_robonomics_config"
IPFS_MEDIA_PATH = "/ha_robonomics_media"
CONFIG_PREFIX = "config-"
CONFIG_ENCRYPTED_PREFIX = "config_encrypted"
BACKUP_PREFIX = "backup-"
BACKUP_ENCRYPTED_PREFIX = "backup_encrypted"
TWIN_ID = "twin_id"

Z2M_CONFIG_NAME = "z2m_data.zip"
Z2M_BACKUP_TOPIC_REQUEST = "zigbee2mqtt/bridge/request/backup"
Z2M_BACKUP_TOPIC_RESPONSE = "zigbee2mqtt/bridge/response/backup"
MQTT_CONFIG_NAME = "mqtt_password"

RWS_DAYS_LEFT_NOTIFY = 5
TIME_CHANGE_COUNT = "time_change_count"
MAX_NUMBER_OF_REQUESTS = 4
SECONDS_IN_DAY = 24 * 60 * 60
IPFS_MAX_FILE_NUMBER = 700

EXCLUDE_FROM_BACKUP = [
    "__pycache__/*",
    ".DS_Store",
    "*.db",
    "*.db-*",
    "*.log.*",
    "*.log",
    "backups/*",
    "OZW_Log.txt",
]
EXCLUDE_FROM_FULL_BACKUP = [
    "__pycache__/*",
    ".DS_Store",
    "*.log.*",
    "*.log",
    "backups/*",
    "OZW_Log.txt",
]

DELETE_ATTRIBUTES = [
    "unit_of_measurement",
    "linkquality",
    "transition",
    "supported_features",
]
ZERO_ACC = "0x0000000000000000000000000000000000000000000000000000000000000000"
MEDIA_ACC_H256 = "0x0000000000000000000000000000000000000000000000000000000000000001"
MEDIA_ACC = "4CC7GkKuJJzFzswqz39m5qWbgXaQks9f36jCgsadpN2c1hnh"
