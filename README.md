Airodump CSV Tools v0.6
by Christopher Bolduc
chris.bolduc@gmail.com

Description:
This is a program I wrote to analyze one or more Airodump CSV files and provide more useful output.

Features:
-Merges the CSV files into one CSV file, html file, or text file, keeping the APs and Stations together.
-Has options to only show APs and Stations that are new or old in the last file you import.
-Optional text output for cron, etc.
-Adds manufacturer info (OUI) to APs and end devices, and the ESSID (if applicable) to end devices, in text/html output modes.
-Adds GPS info captured from optional Android app

Usage: ./csvtools [options] file1 [file2] [file3]...[-l] [file n]
-a only show APs
-b print brief text in text mode
-e only show end devices (stations)
-to prints text to stdout (cannot be used with -t)
-g [file] specifies a GPS input file
-i [file] specifies a CSV file of known IP addresses
-l specifies the last file (must be the last file specified)*
-k [file] specifies a CSV file of known MAC addresses
-m only show APs and Stations in the file specified with -k
-d [delta] only shows devices whose power is stronger than before by [delta]
-n only shows APs and Stations that are new in the last file
-o only shows APs and Stations that are not new in the last file
-p [power] only shows APs and Stations with power greater than [power]
-P [power] only shows APs and Stations with power less than [power]
-sl sort by last time seen
-t only shows APs and Stations greater than the minimum time**
-T only shows APs and Stations less than the maximum time**
-u [server] [port] send findings to UDP server on [server]:[port]
-v verbose output
-vv very verbose output
-w [prefix] specifies output file prefix

*It is not necessary to specify which csv file is the last one (-l), but if you don't, some options won't work properly (-n and -o).
** The minimum and maximum times are currently defined in csvtools.c at the top as constants.

Deprecated Options:
-c specifies a csv file to output to (deprecated by -w)
-t specifies a text file to output to (deprecated by -w)
-h specifies a html file to output to (deprecated by -w)

Installation:
1. Compile using gcc: make
2. Move csvtools to /usr/bin or /usr/local/bin (or symlink it there)

Warranty:
This program is provided as-is without warranty.  Use it at your own risk.

GPS:
There is an Android app included that will capture GPS coordinates from your Android device and save them to a file.  This program will read this file to determine the GPS coordinates for the APs end devices in your airodump .csv file(s).  Run it before you run airodump-ng and stop it after you stop airodump-ng for best results.

To improve its accuracy, you can run this program frequently while you run Airodump (tracker.sh does this once every five seconds).  Doing so will keep the list of maximum power levels for each AP and end device in the files [prefix]-appower.csv and [prefix]-stapower.csv.  After doing this, copy the GPS file from your Android device and run csvtools *again*, with the same -w [prefix] and csv file name, and specify the GPS file with -g.

GPS Example:
1. Start the GPS app on your phone.
2. Enter this in terminal 1: airodump-ng mon0 --output-format=csv -w packets
3. Enter this in terminal 2: ./tracker.sh
4. Drive around and find some APs
5. Stop the apps in terminal 1 and 2.
6. Stop the Android app.
7. Copy the GPS file from your phone to your computer.
8. Run this: csvtools -w test -g [gpsfile] packets-01.csv
9. This will generate test.kml, which can be opened in Google Earth.

SSD Considerations:
Airodump-ng and the tracker.sh script both will perform a lot of disk writes as you run them.  If you have an SSD, it may be wise to create a RAM disk while these programs run and direct their output to the RAM disk.  After running them, you should then copy their output to your hard drive to retain the data after your computer is rebooted, if you desire to keep the output.

Change log:

v0.6 - 2018-09-07
-Added -t and -T options
-Added -u option
-More bug fixes

v0.5 - 2016-08-17
-Finally put prototypes in a header file
-Fixed a few bugs with string processing
-Added the -i option to read known IP addresses
-Used binary search on vendor lookups to improve performance
-Fixed bugs introduced in new code with onlyAddNew and onlyAddOld
-Output now sorted by power level by default

v0.41 - 2015-10-28
-Known MAC address lookup is no longer case sensitive
-Added -D option to show stationary devices

v0.4 - 2015-09-30
-Added new options: -k -m -v -vv
-Added vendor name in the description of the AP/Station in KML (GPS) output file
-Fixed bug in KML file output when the SSID contains a comma or ampersand.
-Fix a major bug with reading the AP and station power level files.  (scanf was used incorrectly.)

v0.3 - 2015-02-04
-Now logs the time and power when each AP/Station's power was at maximum.
-Added new feature to read GPS coordinates from external file (created with optional Android app).
-Changed output file options (-cth) to -w

v0.2
-Added -p and -P power level options
-Added -k option to continuously monitor a csv file
-Added -d option
-Added HTML output (-h)
-Various bug fixes

