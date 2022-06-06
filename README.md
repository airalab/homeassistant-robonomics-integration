# Control Home Assistant with Robonomics

Integration track subscription devices and manage Home Assistant users.

## Installation

In your computer with Home Assistant clone the repository to `custom_componets`:

```bash
sudo -u homeassistant -H -s
cd ~/.homeassistant/custom_components
git clone https://github.com/LoSk-p/home_assistant_users.git robonomics_users
```
> The folder must have name `robonomics_users`

Install ipfs local node:

```bash
cd ~/.homeassistant/custom_components/robonomics_users
chmod +x install_ipfs.sh
./install_ipfs.sh
```

Then restart HOme Assistant:
```bash
systemctl restart home-assistant@homeassistant.service
```

## Configure

For the Robonomics integration you need an [account](https://wiki.robonomics.network/docs/en/create-account-in-dapp/) with [subscription](https://wiki.robonomics.network/docs/en/get-subscription/). Also you need an admin account added to subscription as a device (all accounts should be ed25519 type). Admin account will send telemetry from Home Assistant and will be able to send commands to smart devices.  

In the web interface go to `Settings/Devices & Services/Integrations` and press `Add Integration`. Find `Robonomics`:

![robonomics-users](images/config.png)

Then write mnemonic seeds from Robonomics accounts. Integration use IPFS to save encrypted data, by defaul it uses local node and infura IPFS API, but you can use your Pinata account in addition.
