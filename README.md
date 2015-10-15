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
These plugins are written by various authors and collected from the authors' GitHub repositories, websites and blogs at a particular point in time. We don't guarantee that the plugins you download from this repo will be the most recent ones published by the individual authors. 

contributing
=========

The best way to contribute is to fork the repository, add or modify plugins, and then submit a pull request. 
