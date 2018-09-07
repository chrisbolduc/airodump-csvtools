/*
    Airodump CSV Tools v0.5
    Merges and parses Airodump CSV files and outputs them to CSV, HTML, or text.
    Copyright (C) 2013-2015 Christopher Bolduc

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // Initially added to see what time it is

// Added for execlp in the play_sound function
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define CRLF "\r\n"
#define POWER 1
#define FIRSTSEEN 2
#define LASTSEEN 3
#define HASHTABLE_SZ 65535  // currently 2 bytes

/* I decided it was easier to write my own than use the library.
 * Used by the program to compare dates, not for output.
 */
typedef struct datetime {
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
} datetime;

typedef struct gps {
  datetime dt;
  double lat;
  double lon;

  struct gps *next;
} gps;

// Linked list of Access Points
typedef struct ap {
  char bssid[80];
  char vendor[80];
  char first_time_seen[80];
  char last_time_seen[80];
  char prev_last_time_seen[80];
  char last_time_displayed[80];
  char channel[80];
  char speed[80];
  char privacy[80];
  char cipher[80];
  char authentication[80];
  int power;
  char beacons[80];
  char ivs[80];
  char lan_ip[80];
  char id_length[80];
  char essid[80];
  char key[80];
  // Filename is still left in here from older versions of this program.
  char fileName[80];
  char desc[80];
  char ip[80];
  int oldPower;

  datetime time1;
  datetime time2;
  datetime prvtime2;
  int maxPwrLevel;
  char maxPwrTime[80];
  datetime mpTime;
  double lat;
  double lon;
  int new;
  int old;
  struct ap *next;
} ap;

// Linked list of End Devices
typedef struct enddev {
  char station_mac[80];
  char vendor[80];
  char first_time_seen[80];
  char last_time_seen[80];
  char prev_last_time_seen[80];
  char last_time_displayed[80];
  int power;
  char packets[80];
  char bssid[80];
  char essid[80];
  char channel[80];
  char probed_essids[255];
  char fileName[80];
  char desc[80];
  char ip[80];
  int oldPower;

  datetime time1;
  datetime time2;
  datetime prvtime2;
  int maxPwrLevel;
  char maxPwrTime[80];
  datetime mpTime;
  double lat;
  double lon;
  int new;
  int old;
  struct enddev *next;
} enddev;

typedef struct macdb {
  char mac[18];
  char vendor[80];
  char essid[80];

  struct macdb *next;
} macdb;

typedef struct devset {
  ap *s;
  enddev *e;
} devset;

typedef struct aplist {
  ap *data;
  struct aplist *next;
} aplist;

typedef struct stalist {
  enddev *data;
  struct stalist *next;
} stalist;

// Prototypes
int compareApByMac ( const void *p1, const void *p2 );
int compareApByPwr ( const void *p1, const void *p2 );
int compareApFirstseen ( const void *p1, const void *p2 );
int compareApLastseen ( const void *p1, const void *p2 );
int compareStaByMac ( const void *p1, const void *p2 );
int compareStaByPwr ( const void *p1, const void *p2 );
int compareStaFirstseen ( const void *p1, const void *p2 );
int compareStaLastseen ( const void *p1, const void *p2 );
int compareMacdb ( const void *p1, const void *p2 );
int getMacHash ( const char *mac );
int addApToHT(aplist *ht, ap *a);
ap *findApHT (aplist *aps, const char *mac);
int addStaToHT(stalist *ht, enddev *e);
enddev *findStaHT (stalist *stl, const char *mac);
char *str_replace(char *s, char old, char new);
int strToTime (datetime *dest, const char *str);
char *timeToStr(const datetime *src, char *str);
int compareDates (datetime *d1, datetime *d2);
int compareToNow (const char *lastTimeSeen, const char *thresh);
void getNowStr (char * str);
void free_ap (ap *s);
void free_enddev (enddev *e);
void free_aplist (aplist *a);
void free_ht_ap (aplist *aps);
void free_stalist (stalist *s);
void free_ht_sta (stalist *sts);
void free_gps (gps *g);
int isValidMacAddress(const char* mac);
long getEssid(char *currWord, char *buffer, long i, long lSize);
long getWord(char *currWord, char *buffer, long i, long lSize);
ap *findApByBSSID (ap *s, char *key);
char *findVendorByMACBin (macdb * m, int mac_db_sz, const char * key);
char *findVendorByMAC (macdb * m, char * key);
devset readCSVFile (char * fileName, ap *firstAp, enddev *firstEnddev, const int lastFile);
void readMacDB (char * fileName);
void readKnownMacs (char * fileName);
void readKnownIPs (char * fileName);
void addGPSInfo (ap *firstap, enddev *firsted, gps *firstg);
void printAPToFileKML (ap *a, FILE *f);
void printEndDeviceToFileKML (enddev *e, FILE *f);
gps *readGPSFile (ap *firstap, enddev *firsted, FILE *f);
void readAPPowerFromFile (ap *first, FILE *f);
void readEnddevPowerFromFile (enddev *first, FILE *f);
void printAPPowerToFile (ap *a, FILE *f);
void printAPPowerToFileRec (ap *a, FILE *f);
void printEndDevicesPowerToFile (enddev *e, FILE *f);
void printEndDevicesPowerToFileRec (enddev *e, FILE *f);
void readAPDisplayedFromFile (ap *first, FILE *f);
void readEnddevDisplayedFromFile (enddev *first, FILE *f);
void printAPDisplayedToFile (ap *a, FILE *f);
void printEndDevicesDisplayedToFile (enddev *e, FILE *f);
void printAPToFileText (ap *a, FILE *f);
//void printAPsToFileText (ap *a, FILE *f);
void printEndDeviceToFileText (enddev *e, FILE *f);
//void printEndDevicesToFileText (enddev *e, FILE *f);
void printAPToFileCSV (ap *a, FILE *f);
void printAPsToFileRec (ap *a);
void printEndDeviceToFileCSV (enddev *e, FILE *f);
void printEndDevicesToFileRec (enddev *e);
void printAPToFileHTML (ap *a, FILE *f);
//void printAPsToFileHTML (ap *a, FILE *f);
void printEndDeviceToFileHTML (enddev *e, FILE *f);
//void printEndDevicesToFileHTML (enddev *e, FILE *f);
