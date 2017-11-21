community
=========

Volatility plugins developed and maintained by the community. See the README file inside each author's subdirectory for a link to their respective GitHub profile page where you can find usage instructions, dependencies, license information, and future updates for the plugins. 

usage
=========

1. Git clone the [Volatility](https://github.com/volatilityfoundation/volatility) repository or [Download a Release](http://www.volatilityfoundation.org/#!releases/component_71401)
2. Git clone this repository to $PLUGINSPATH
3. Pass the --plugins=$PLUGINSPATH option to Volatility when you run it (see [Specifying Additional Plugin Directories](https://github.com/volatilityfoundation/volatility/wiki/Volatility%20Usage#specifying-additional-plugin-directories))

NOTE: If you pass the root of the $PLUGINSPATH directory, then all plugins will recursively be loaded. Its possible that plugins may try to register the same command line options and produce a conflict. If this happens, just point --plugins at one or more specific subdirectories (`:` separated on Linux/Mac or `;` separated on Windows). 

disclaimer
=========
These plugins are written by various authors and collected from the authors' GitHub repositories, websites and blogs at a particular point in time. We don't guarantee that the plugins you download from this repo will be the most recent ones published by the individual authors, that they're compatible with the most recent version of Volatility, or that they report results accurately. 

contributing
=========

The best way to contribute is to fork the repository, add or modify plugins, and then submit a pull request. 

frameworks 
=========

Researchers and developers in the community have also created frameworks that build on top of Volatility. These aren't necessarily Volatility plugins (that you would import with --plugins) and usually they contain additional modules, configurations, and components. For that reason, we don't feature those frameworks in this repository, but we'd still like to reference them: 

* [Autopsy Plugins](https://github.com/markmckinnon/Autopsy-Plugins/tree/master/Volatility) by Mark McKinnon
* [PyREBox](https://github.com/Cisco-Talos/pyrebox) by Xabier Ugarte-Pedrero at Cisco Talos
* [Cuckoo Sandbox](https://github.com/cuckoobox/cuckoo) uses Volatility for its Memory module
* [VolDiff](https://github.com/aim4r/VolDiff) Malware Memory Footprint Analysis by @aim4r
* [Evolve](https://github.com/JamesHabben/evolve) Web interface for the Volatility Memory Forensics Framework by James Habben
* [GVol](https://github.com/eg-cert/GVol) Lightweight GUI (Java) by EG-CERT
* [LibVMI](https://github.com/libvmi/libvmi) Simplified Virtual Machine Introspection 
* [DAMM](https://github.com/504ensicsLabs/DAMM) Differencial Analysis of Malware in Memory
* [YaraVol](https://bitbucket.org/Ft44k/yavol/) GUI for Volatility Framework and Yara
* [VolUtility](https://github.com/kevthehermit/VolUtility) Web Interface for Volatility by Kevin Breen
* [ROPMEMU](https://github.com/vrtadmin/ROPMEMU) A framework to analyze, dissect and decompile complex code-reuse attacks by Mariano Graziano 
* [VolatilityBot](https://github.com/mkorman90/VolatilityBot) An automated memory analyzer for malware samples and memory dumps by Martin Korman
* [ProfileScan](https://github.com/P1kachu/VolatilityProfileScan) Profile detection for Volatility by Stanislas Lejay (P1kachu)

Don't see your project here? Let us know by submitting a pull request, creating an issue, or tweet us at @volatility. 
