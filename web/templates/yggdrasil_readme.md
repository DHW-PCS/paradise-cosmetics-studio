# Yggdrasil API for Paradise Cosmetics Studio

The Yggdrasil module lets Minecraft clients sign in with a PCS account and load the skins and capes assigned to its characters.

## Connect a launcher

Enable the Yggdrasil module and copy the API root from its configuration page. Use the full URL, including `/api/yggdrasil` and any site path before it. Add that URL as an account server in a launcher that supports [authlib-injector](https://github.com/yushijinhun/authlib-injector), then sign in with your site account.

For development, see the [Yggdrasil server specification](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil%20%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83). The [Blessing Skin Yggdrasil guide](https://blessing.netlify.app/yggdrasil-api/) describes the upstream plugin and client setup. Use the PCS admin panel for server configuration.
