# volatility-wnf

See https://github.com/citronneur/volatility-wnf/ for update.

Browse and dump Windows Notification Facilities

This plugin is based on work of Alex Ionescu and Gabrielle Viala.

[https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html]
[https://www.blackhat.com/us-18/briefings/schedule/#the-windows-notification-facility-peeling-the-onion-of-the-most-undocumented-kernel-attack-surface-yet-11626]
[https://www.youtube.com/watch?v=MybmgE95weo]

This plugin just walk through all process, or by filter one, and dump all subscribers.
Additionnaly, it can dump associated data from a subscriber.

## Install

Please put *wnf.py* in your volatility plugin folder.

## Use

To dump all subscribers of all process
```
python vol.py -f your_dump --profile=your_profile wnf
```

To dump all subscriber of a particular process
```
python vol.py -f your_dump --profile=your_profile wnf --pid PID
```

To dump data associated to a particular subscriber
```
python vol.py -f your_dump --profile=your_profile wnfdata -s ADRESS_OF_SUBSCRIBER
```

ADRESS_OF_SUBSCRIBER is the first field dump from wnf command.