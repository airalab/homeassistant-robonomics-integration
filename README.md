# Control Home Assistant users with Robonomics

Integration track subscription devices and manage Home Assistant users.

## Installation

In your computer with Home Assistant clone the repository to `custom_componets`:

```bash
sudo -u homeassistant -H -s
cd ~/.homeassistant/custom_components
git clone https://github.com/LoSk-p/home_assistant_users.git robonomics_users
```

Install dependensies:

```bash
source /srv/homeassistant/bin/activate
cd ~/.homeassistant/custom_components/robonomics_users
pip3 install -r requirements.txt
```

Write mnemonic seed from the account you want to add to subscription and subscription owner address (both of them must be ed25519 type) to `config.py`:
```bash
nano cd ~/.homeassistant/custom_components/robonomics_users/config.py
```
It must look like this:
```
SUB_OWNER_ADDRESS = "address"
USER_SEED = "word word word ..."
```

## Run

Restart Home Assistant:

```bash
systemctl restart home-assistant@homeassistant.service
```

In the web interface go to `Configuration/Integrations` and press `Add Integration`. Find `Robonomics Users Control`:

![robonomics-users]()

Then write mnemonic seed from subscription owner account and press `submit`.

## Use

Run `get_credentials.py` script:
```bash
sudo -u homeassistant -H -s
source /srv/homeassistant/bin/activate
cd ~/.homeassistant/custom_components/robonomics_users
python3 get_credentials.py
````

Add device to the subscription and `get_credentials.py` will show new username and password.