# MHW-SafeNet
SafeNet is a small plugin for Monster Hunter: World that _**could**_ prevent de-serialization attacks (with type confusion) against the MHW game client over SteamWorks P2P networking, potentially allowing full remote code execution.

There are no claims that you need this plugin for MHW to be safe, nor any claims that this fully protects the client from de-serialization attacks. However, I will personally be making sure that this is enabled myself whenever I start the client from now on, as the client has ASLR disabled and doesn't properly authenticate P2P packets over ISteamNetworking.

## Installation
(Requires [Strackeror](https://github.com/Strackeror)'s [MHW plugin loader](https://www.nexusmods.com/monsterhunterworld/mods/1982))

Copy the latest release build `.dll` into the`{GAMEFOLDER}/NativePC/plugins` folder.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)