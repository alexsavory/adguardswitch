# homebridge-adguard-dns-switch

A Homebridge plugin to toggle the AdGuard DNS protection feature via a switch accessory. Individual device toggles are not supported via the API, so any devices attached to a server will not be protected from the blocklists.

**This is not compatiable with AdGuard Home systems**

## Configuration

Enter your username and password for the Adguard DNS Dashboard <br>
Select a server from your list and use the server_id from the url for the plugin. <br>

**Multi-Factor Authentication or Passwordless profiles are not supported at the moment, you will need to setup a password for your AdGuard Account**