"""Constants for the Robonomics Control integration."""

DOMAIN = "robonomics"
CONF_IP = "ip"
PLATFORMS = []

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

IPFS_GATEWAY = "https://ipfs.io/ipfs/"
MORALIS_GATEWAY = "https://gateway.moralisipfs.com/ipfs/"
LOCAL_GATEWAY = "http://localhost:8080/ipfs/"

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
CONFIG_PREFIX = "config-"
CONFIG_ENCRYPTED_PREFIX = "config_encrypted"
BACKUP_PREFIX = "backup-"
BACKUP_ENCRYPTED_PREFIX = "backup_encrypted"
TWIN_ID = "twin_id"

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
