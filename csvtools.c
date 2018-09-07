/*
    Airodump CSV Tools v0.5
    Merges and parses Airodump CSV files and outputs them to CSV, HTML, or text.
    Copyright (C) 2013-2018 Christopher Bolduc

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

#include "csvtools.h"

#define MINTIME "0000-00-00 00:30:00"
#define MAXTIME "0001-00-00 00:00:00"

// Boolean Globals
int onlyAddCommon;
int onlyAddNew;
int onlyAddOld;
int onlyShowKnown;
int deltaSpecified;
int text_brief;
int timeMax;
int timeMin;

// Other Globals
int sortBy;
int verbosity;
int numInputFiles;
int minPower;
int maxPower;
int minPowerDelta;
int mac_db_sz;
int known_macs_sz;
int ap_count;
int sta_count;
FILE *kmlFile, *textFile, *htmlFile, *csvFile;
macdb *mac_database, *known_macs, *known_ips;
char *remoteserver;
int remoteport;
enddev *firstEnddevDbg;
macdb *extraSta;
int extraStaCt;
aplist aptable[HASHTABLE_SZ];
stalist statable[HASHTABLE_SZ];
int collisions;

int compareApByMac ( const void *p1, const void *p2 ) {
  const ap *ap1 = (ap*) p1;
  const ap *ap2 = (ap*) p2;

  return strcmp (ap1->bssid, ap2->bssid);
}

int compareApByPwr ( const void *p1, const void *p2 ) {
  const ap **app1 = (ap**) p1;
  const ap **app2 = (ap**) p2;

  const ap *ap1 = *app1;
  const ap *ap2 = *app2;

  return ap2->power - ap1->power; // sort highest to lowest
}

int compareApLastseen ( const void *p1, const void *p2 ) {
  const ap **app1 = (ap**) p1;
  const ap **app2 = (ap**) p2;

  const ap *ap1 = *app1;
  const ap *ap2 = *app2;

  datetime d1, d2;

  strToTime(&d1, ap1->last_time_seen);
  strToTime(&d2, ap2->last_time_seen);

  return compareDates(&d2, &d1); // sort highest to lowest
}

int compareApFirstseen ( const void *p1, const void *p2 ) {
  const ap **app1 = (ap**) p1;
  const ap **app2 = (ap**) p2;

  const ap *ap1 = *app1;
  const ap *ap2 = *app2;

  datetime d1, d2;

  strToTime(&d1, ap1->first_time_seen);
  strToTime(&d2, ap2->first_time_seen);

  return compareDates(&d2, &d1); // sort highest to lowest
}


int compareStaByMac ( const void *p1, const void *p2 ) {
  const enddev *e1 = (enddev*) p1;
  const enddev *e2 = (enddev*) p2;

  return strcmp (e1->station_mac, e2->station_mac);
}

int compareStaByPwr ( const void *p1, const void *p2 ) {
  const enddev **ep1 = (enddev**) p1;
  const enddev **ep2 = (enddev**) p2;

  const enddev *e1 = *ep1;
  const enddev *e2 = *ep2;
  if (e1->power > e2->power) return -1; // sort highest to lowest
  if (e1->power < e2->power) return 1;
  return 0;
}

int compareStaLastseen ( const void *p1, const void *p2 ) {
  const enddev **ep1 = (enddev**) p1;
  const enddev **ep2 = (enddev**) p2;

  const enddev *e1 = *ep1;
  const enddev *e2 = *ep2;

  datetime d1, d2;

  strToTime(&d1, e1->last_time_seen);
  strToTime(&d2, e2->last_time_seen);

  return compareDates(&d2, &d1); // sort highest to lowest
}

int compareStaFirstseen ( const void *p1, const void *p2 ) {
  const enddev **ep1 = (enddev**) p1;
  const enddev **ep2 = (enddev**) p2;

  const enddev *e1 = *ep1;
  const enddev *e2 = *ep2;

  datetime d1, d2;

  strToTime(&d1, e1->first_time_seen);
  strToTime(&d2, e2->first_time_seen);

  return compareDates(&d2, &d1); // sort highest to lowest
}

int compareMacdb ( const void *p1, const void *p2 ) {
  const macdb *d1 = (macdb*) p1;
  const macdb *d2 = (macdb*) p2;

  return strcmp (d1->mac, d2->mac);
}

// Return the int value 0-15 for an ascii hex char
int charToHex( char c ) {
  if (c >= 0x30 && c <= 0x39) // digit
    return c - 0x30;
  if (c >= 0x41 && c <= 0x46) // uppercase
    return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) // lowercase
    return c - 0x61 + 10;
  return -1;
}

// hash the mac based on last 2 bytes (least-significant)
int getMacHash ( const char *mac ) {
  int hash, ret;
  if (strlen(mac) < 17) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Malformed MAC address %s (too short)\n", mac);
    return -1;
  }
  ret = charToHex( mac[16] );
  if (ret == -1) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Malformed MAC address %s (char 16)\n", mac);
    return -1;
  }
  hash = ret;
  ret = charToHex( mac[15] );
  if (ret == -1) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Malformed MAC address %s (char 15)\n", mac);
    return -1;
  }
  hash += ret << 4;
  ret = charToHex( mac[13] );
  if (ret == -1) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Malformed MAC address %s (char 13)\n", mac);
    return -1;
  }
  hash += ret << 8;
  ret = charToHex( mac[12] );
  if (ret == -1) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Malformed MAC address %s (char 12)\n", mac);
    return -1;
  }
  hash += ret << 12;
  if (hash > HASHTABLE_SZ || hash < 0) {
    if (verbosity >= 2) fprintf (stderr, "getMacHash: Hash > HASHTABLE_SZ or < 0 MAC: %s\n", mac);
    return -1;
  }
//  printf ("getMacHash: returning hash of %d\n", hash);
  return hash;
}

int addApToHT(aplist *ht, ap *a) {
  if (verbosity >= 2) printf ("addApToHT: Adding %s\n", a->bssid);
  int hash = getMacHash(a->bssid);
  if (hash == -1) {
    if (verbosity >= 2) fprintf (stderr, "addApToHT: getMacHash returned error\n");
    return -1;
  }
  aplist *list1 = ht + hash;
  if (list1->data == NULL) {
//    list1 = (aplist *) malloc(sizeof(aplist)); // already alloc'ed
//    if (list1 == NULL) return -1;
    list1->data = a;
    list1->next = NULL;
//    if (verbosity >= 2) printf("addApToHT: added %s to first node\n", a->bssid);
    return 0;
  }
  while (list1->next != NULL) {
    list1 = list1->next;
  }
  list1->next = (aplist *) malloc(sizeof(aplist));
  if (list1->next == NULL) return -1;
  list1->next->data = a;
  list1->next->next = NULL;
  return 0;
}

ap *findApHT (aplist *aps, const char *mac) {
  if (verbosity >= 2) printf("findApHT: looking for %s\n", mac);
  int hash = getMacHash(mac);
  if (hash == -1) {
    if (verbosity >= 2) fprintf (stderr, "findApHT: getMacHash returned error\n");
    return NULL;
  }
  aplist *list1 = aps + hash;
/* not possible
  if (list1 == NULL) {
    fprintf (stderr, "findAp: hash for this entry is null (%s)\n", mac);
    return NULL;
  }
*/
  while (list1 != NULL) {
    if (list1->data == NULL) {
      if (verbosity >= 2) printf("findApHT: not found 1\n");
      return NULL; // not found - array gets alloc'ed even if we don't want it to
    }
//    printf("Comparing %s to %s\n", mac, list1->data->bssid);
    if (strcmp(mac, list1->data->bssid) == 0) {
//      printf("findApHT: found\n");
      return list1->data;
    }
    list1 = list1->next;
  }
  return NULL; // not found
}

int addStaToHT(stalist *ht, enddev *e) {
  if (verbosity >= 2) printf ("addStaToHT: Adding %s\n", e->station_mac);
  int hash = getMacHash(e->station_mac);
  if (hash == -1) {
    if (verbosity >= 2) fprintf (stderr, "addStaToHT: getMacHash returned error\n");
    return -1;
  }
  stalist *list1 = ht + hash;
  if (list1->data == NULL) {
//    list1 = (aplist *) malloc(sizeof(aplist)); // already alloc'ed
//    if (list1 == NULL) return -1;
    list1->data = e;
    list1->next = NULL;
//    printf("addStaToHT: added %s to first node\n", e->station_mac);
    return 0;
  }
  while (list1->next != NULL) {
    list1 = list1->next;
  }
  list1->next = (stalist *) malloc(sizeof(stalist));
  if (list1->next == NULL) return -1;
  list1->next->data = e;
  list1->next->next = NULL;
//  printf("addStaToHT: added %s to additional node\n", e->station_mac);
  return 0;
}

enddev *findStaHT (stalist *stl, const char *mac) {
  if (verbosity >= 2) printf("findStaHT: looking for %s\n", mac);
  int hash = getMacHash(mac);
  if (hash == -1) {
    if (verbosity >= 2) fprintf (stderr, "findStaHT: getMacHash returned error\n");
    return NULL;
  }
  stalist *list1 = stl + hash;
/* not possible
  if (list1 == NULL) {
    fprintf (stderr, "findAp: hash for this entry is null (%s)\n", mac);
    return NULL;
  }
*/
  while (list1 != NULL) {
    if (list1->data == NULL) {
      if (verbosity>=2) printf("findStaHT: not found 1 - %s\n", mac);
      return NULL; // not found - array gets alloc'ed even if we don't want it to
    }
//    printf("Comparing %s to %s\n", mac, list1->data->station_mac);
    if (strcmp(mac, list1->data->station_mac) == 0) {
//      printf("findStaHT: found %s\n", mac);
      return list1->data;
    }
//    printf ("Hash collision on %s (%s)\n", list1->data->station_mac, mac);
    collisions++;
    list1 = list1->next;
  }
  if (verbosity>=2) printf("findStaHT: not found 2 - %s\n", mac);
  return NULL; // not found
}

// Replace a character in a string
char *str_replace(char *s, char old, char new) {
  char *p = s;

  while(*p) {
    if(*p == old)
    *p = new;
    ++p;
  }

  return s;
}

int strToTime (datetime *dest, const char *str) {
  return sscanf (str, "%d-%d-%d %d:%d:%d",
      &(dest->year),
      &(dest->month),
      &(dest->day),
      &(dest->hour),
      &(dest->minute),
      &(dest->second));
}

char *timeToStr(const datetime *src, char *str) {
  sprintf(str, "%04d-%02d-%02d %02d:%02d:%02d", src->year, src->month, src->day, src->hour, src->minute, src->second);
  return str;
}

int daysInMonth (int month, int year) {
  int leapyear = 0;

  if (month > 12 || month < 1) {
    fprintf(stderr, "daysInMonth(): Invalid month (%d)\n", month);
    enddev *curr = firstEnddevDbg;
    while (curr != NULL) {
      printEndDeviceToFileText(curr, stderr);
      curr = curr->next;
    }
    return -1;
  }
  if (year % 100 == 0 && year % 400 != 0) {
    leapyear = 0;
  } else if (year % 4 == 0) {
    leapyear = 1;
  } else {
    leapyear = 0;
  }

  switch(month) {
  case 2:
  if (leapyear)
    return 29;
  return 28;
  case 4:
  case 6:
  case 9:
  case 11:
    return 30;
  default:
    return 31;
  }
}

// Places in delta the amount of time between d1 and d2
void dateDiff (datetime *delta, const datetime *d1, const datetime *d2) {
  memcpy(delta, d1, sizeof(datetime));
  char timebuf[24];

//  printf("d1: %s\n", timeToStr(d1, timebuf));
//  printf("delta: %s\n", timeToStr(delta, timebuf));
  if (delta->second < d2->second) {
    delta->minute--;
    delta->second += 60;
  }
//  printf ("delta: %s\n", timeToStr(delta, timebuf));
  delta->second -= d2->second;
//  printf ("delta: %s\n", timeToStr(delta, timebuf)); 
  if (delta->minute < d2->minute) {
    delta->hour--;
    delta->minute += 60;
  }
  delta->minute -= d2->minute;
  if (delta->hour < d2->hour) {
    delta->day--;
    delta->hour += 24;
  }
  delta->hour -= d2->hour;
  if (delta->day < d2->day) {
    delta->month--;
    int offset;
    if (delta->month <= 0) {
      offset = daysInMonth(delta->month+12, delta->year-1);
    } else {
      offset = daysInMonth(delta->month, delta->year);
    }
    if (offset == -1) {
      char b1[30], b2[30];
      timeToStr(d1, b1);
      timeToStr(d2, b2);
      fprintf(stderr, "dateDiff: invalid date received, d1: %s, d2: %s\n", b1, b2);
    }
    delta->day += offset;
  }
  delta->day -= d2->day;
  if (delta->month < d2->month) {
    delta->year--;
    delta->month += 12;
  }
  delta->month -= d2->month;
  delta->year -= d2->year;
  if (delta->year < 0) {
    // d1 is later than d2
    dateDiff(delta, d2, d1);
  }
}

// Returns 1 if d1 > d2, -1 if d2 > d1, 0 if equal
int compareDates (datetime *d1, datetime *d2) {
  if (d1->year > d2->year) return 1;
  if (d1->year < d2->year) return -1;
  if (d1->month > d2->month) return 1;
  if (d1->month < d2->month) return -1;
  if (d1->day > d2->day) return 1;
  if (d1->day < d2->day) return -1;
  if (d1->hour > d2->hour) return 1;
  if (d1->hour < d2->hour) return -1;
  if (d1->minute > d2->minute) return 1;
  if (d1->minute < d2->minute) return -1;
  if (d1->second > d2->second) return 1;
  if (d1->second < d2->second) return -1;
  return 0;
}

void getNowStr(char * buffer) {
  time_t timer;
  struct tm* tm_info;

  time(&timer);
  tm_info = localtime(&timer);
  strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

}

char *dateHuman(const datetime *d, char *str) {
  if (d->year != 0) {
    sprintf(str, "%dy%dm", d->year, d->month);
    return str;
  }
  if (d->month != 0) {
    sprintf(str, "%dm%dd", d->month, d->day);
    return str;
  }
  if (d->day != 0) {
    sprintf(str, "%dd%dh", d->day, d->hour);
    return str;
  }
  if (d->hour != 0) {
    sprintf(str, "%dh%dm", d->hour, d->minute);
    return str;
  }
  sprintf(str, "%dm%ds", d->minute, d->second);
  return str;

}

char *dateHumanLong(const datetime *d, char *str) {
  if (d->year != 0) {
    sprintf(str, "%d years", d->year);
    return str;
  }
  if (d->month != 0) {
    sprintf(str, "%d months", d->month);
    return str;
  }
  if (d->day != 0) {
    sprintf(str, "%d days", d->day);
    return str;
  }
  if (d->hour != 0) {
    sprintf(str, "%d hours", d->hour);
    return str;
  }
  if (d->minute != 0) {
    sprintf(str, "%d minutes", d->minute);
    return str;
  }
  sprintf(str, "%d seconds", d->second);
  return str;

}

/* Returns +1 if lastTimeSeen > thresh, 0 if equal,
 * -1 if lastTimeSeen < thresh
 */
int compareToNow (const char *lastTimeSeen, const char *thresh) {
  time_t timer;
  char buffer[26];
  struct tm* tm_info;

  time(&timer);
  tm_info = localtime(&timer);
  strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

  // Only show devices where last_time_seen was 30 minutes ago or less
  datetime delta, lastSeen, now, timethresh;
  bzero(&delta, sizeof(delta));
  strToTime(&lastSeen, lastTimeSeen);
  strToTime(&now, buffer);
  strToTime(&timethresh, thresh);
//  printf("Now: %s Last time seen: %s ", buffer, lastTimeSeen);
  dateDiff (&delta, &lastSeen, &now);
//  printf("Delta: %s >Thresh?: %d\n", timeToStr(&delta, buffer), compareDates(&delta, &timethresh));
  return compareDates(&delta, &timethresh);
}

// Free the linked list of APs
void free_ap (ap *s) {
  if (s == NULL) return;
  free_ap(s->next);
  free(s);
}

// Free the linked list of Enddevs
void free_enddev (enddev *e) {
  if (e == NULL) return;
  free_enddev(e->next);
  free(e);
}

// Free the hashtable collision items
void free_aplist (aplist *a) {
  if (a == NULL) return;
  free_aplist(a->next);
  free(a);
}

void free_ht_ap (aplist *aps) {
  int i;
  aplist *curr;
  for (i=0; i < HASHTABLE_SZ; i++) {
    curr = aps + i;
    free(aps->next);
  }
}

void free_stalist (stalist *s) {
  if (s == NULL) return;
  free_stalist(s->next);
  free(s);
}

void free_ht_sta (stalist *sts) {
  int i;
  stalist *curr;
  for (i=0; i < HASHTABLE_SZ; i++) {
    curr = sts + i;
    free(sts->next);
  }
}

// Free the linked list of GPS times and coordinates
void free_gps (gps *g) {
  if (g == NULL) return;
  free_gps(g->next);
  free(g);
}

// airodump does not always give us properly formatted csv output
int isValidMacAddress(const char* mac) {
    int i = 0;
    int s = 0;

    while (*mac) {
       if (isxdigit(*mac)) {
          i++;
       }
       else if (*mac == ':' || *mac == '-') {

          if (i == 0 || i / 2 - 1 != s)
            break;

          ++s;
       }
       else {
           s = -1;
       }


       ++mac;
    }

    return (i == 12 && (s == 5 || s == 0));
}

int send_info_udp(char *hostname, int portno, char *msg) {
    int sockfd, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;

    if (msg == NULL) {
      fprintf(stderr, "send_info_udp err: msg null\n");
      return 1;
    }

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        return 1;
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
//    serveraddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    serveraddr.sin_port = htons(portno);

    /* send the message to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, msg, strlen(msg), 0, (const struct sockaddr *) &serveraddr, (socklen_t) serverlen);
    if (n < 0)
      error("ERROR in sendto");

    return 0;
}

// http://cboard.cprogramming.com/linux-programming/105923-c-program-play-sound.html
// 2015-08-18
void play_sound (char *path) {
  pid_t x;      // a special kind of int
//  char kil[20] = "kill -s 9 ";

  x = fork();   /* now there's actually two "x"s:
if fork succeeds, "x" to the CHILD PROCESS is the return value of fork (0)
and "x" to the PARENT PROCESS is the actual system pid of the child process.*/

  if (x < 0) {  // just in case fork fails 
    puts("fork failure");
    return;
  }
  else if (x == 0) { // therefore this block will be the child process 
    execlp("mpg123", "mpg123", "-q", path, (char *)NULL);
  }
/*                   // see GNU docs, "system" also works                
  else {
    printf("from parent: mpg123 is pid %d\nENTER to quit\n", x);
    sprintf(kil,"%s%d",kil,x);
    getchar();  // wait for user input
    system(kil);
    printf("All ");
  }
*/
}

// This is a separate function from getWord in case the ESSID has commas in it
long getEssid(char *currWord, char *buffer, long i, long lSize) {
  long lastComma = 0;
  int j = i;
  // Skip leading whitespace
  while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

  while (j < lSize-1) {
    if (buffer[j] == '\r' && buffer[j+1] == '\n') {
      break;
    }
    if (buffer[j] == ',') {
      lastComma = j;
    }
    j++;
  }

  j=0;
  while (i < lastComma && i < lSize-1) {
    currWord[j] = buffer[i];
    i++;
    j++;
  }
  i++;
  j++;
  currWord[j] = '\0';
  return i;
}

// Reads one word from the input file (buffer) and places it into currWord
// Returns the position in buffer
long getWord(char *currWord, char *buffer, long i, long lSize) {
  long j=0;

  // Skip leading whitespace
  while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

  while (i < lSize-1) {
    if (buffer[i] == '\r' && buffer[i+1] == '\n') {
      // Why, Microsoft?
      i += 2;
      currWord[j] = '\0';
//      printf ("getWord: %s\n", currWord);
      return i;
    }
    if (buffer[i] == ',' || buffer[i] == '\n') {
      currWord[j] = '\0';
//      printf ("getWord: %s\n", currWord);
      i++;
      return i;
    }
    currWord[j] = buffer[i];
    i++;
    j++;
  }
  return i;
}

// Finds an AP in the linked list given the BSSID (key)
ap *findApByBSSID (ap *s, char *key) {
  if (!s) return NULL;
  if (strcmp (s->bssid, key) == 0) {
//    printf("Found %s\n", key);
    return s;
  }
  return findApByBSSID(s->next, key);
}

// Binary search for the Vendor
// Requires macdb to be a sorted array
char *findVendorByMACBin (macdb * m, int mac_db_sz, const char * key) {
  int first, middle, last;
//  printf ("Searching for: %s\n", key);
  if (!m) return "";

/* This was to check for segfaults
  printf("Vendors: %d\n", mac_db_sz); 
  int i;
  char *a, *b;
  for (i=0; i<mac_db_sz; i++) {
    a = m[i].mac;
    b = m[i].vendor;
  }
  printf("all vendors done\n");
*/
  first = 0;
  last = mac_db_sz - 1;
  middle = (first + last) / 2;

  while (first <= last) {
    if (strcmp(m[middle].mac, key) < 0) {
      first = middle + 1;
    } else if (strcmp(m[middle].mac, key) == 0) {
//      printf ("MAC: %s VEN: %s\n", m[middle].mac, m[middle].vendor);
      return m[middle].vendor;
    } else {
      last = middle - 1;
    }
    middle = (first + last) / 2;
  }
//  printf ("Not found: %s\n", key);
  return ""; // not found
}

char *findVendorByMAC (macdb * m, char * key) {
//  printf ("Searching for: %s\n", key);
  if (!m) return "";
  if (strcmp(m->mac, key) == 0) return m->vendor;
//  if (m->next == NULL) return "";
  return findVendorByMAC(m->next, key);
}

// Finds an Enddev in the linked list given the Station MAC (key)
enddev *findEnddevByMAC (enddev *e, char *key) {
  if (e == NULL) return NULL;
  if (strcmp (e->station_mac, key) == 0) return e;
//  if (e->next == NULL) return NULL;
  return findEnddevByMAC(e->next, key);
}

//void printAPAlert (ap *a) {
//  printf ("BSSID %s seen at %s", a->bssid, a->last_time_seen);
//}

// Prints a single AP to a file with its max power level 
void printAPPowerToFile (ap *a, FILE *f) {
//  printf ("%s, %d, %s%s", a->bssid, a->maxPwrLevel, a->maxPwrTime, CRLF);
  fprintf (f, "%s, %d, %s%s", a->bssid, a->maxPwrLevel, a->maxPwrTime, CRLF);
}

void printAPPowerToFileRec (ap *a, FILE *f) {
  int result;
  int i;
  ap *currAp = a;

  if (a == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  if (verbosity >= 2) printf("Printing AP Power to file: %s\n", a->bssid);
  printAPPowerToFile (a, f);

  result = ferror (f);
  if (result) {
    printf ("printAPsPowersToFile fprintf returned error: %d\n", result);
    return;
  }
  printAPPowerToFileRec (a->next, f);
}

void printEndDevicesPowerToFile (enddev *e, FILE *f) {
  fprintf (f, "%s, %d, %s%s", e->station_mac, e->maxPwrLevel, e->maxPwrTime, CRLF);
//  printf ("%s, %d, %s%s", e->station_mac, e->maxPwrLevel, e->maxPwrTime, CRLF);
}

// Prints power levels from a linked list of Enddevs (e) to a file (f)
void printEndDevicesPowerToFileRec (enddev *e, FILE *f) {
  int result;
  int i;
  enddev *curr = e;

  if (e == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  printEndDevicesPowerToFile (e, f);

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesPowersToFile fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesPowerToFileRec (e->next, f);
}

// sz is populated by the function
// returned string will need to be freed
char *readFileToString(FILE *pFile, long *sz) {
  long lSize;
  char *buffer;
  size_t result;

  // obtain file size
  fseek (pFile, 0, SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  // allocate memory to contain the whole file
  buffer = (char*) malloc(sizeof(char) * lSize);
  if (buffer == NULL) {
    fputs ("Memory error\n", stderr);
    exit(2);
  }

  // copy the file into the buffer
  result = fread (buffer, 1, lSize, pFile);
  if (result != lSize) {
    fputs ("Reading error\n", stderr);
    exit(3);
  }
//  fclose(pFile);
  *sz = lSize;
  return buffer;
}

void readAPPowerFromFile (ap *first, FILE *f) {
  ap *curr;
  char bssid[80];
  char pwrbuf[80];
  char time[80];
  char *buffer;
  int power;
  int result;
  long lSize;

  if (first == NULL) return;
  buffer = readFileToString(f, &lSize);
  long i=0;
  int j=0;
  while (i<lSize) {
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',') {
        bssid[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        fprintf (stderr, "Error: unexpected EOL for bssid %s\nbuffer: %s\n", bssid, buffer);
        return;
      }
      else
        bssid[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("bssid: %s ", bssid);
    while (buffer[i] == ' ') i++;
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',')  {
        pwrbuf[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        fprintf (stderr, "Error: unexpected EOL for bssid %s\n,buffer:%s\n", bssid, buffer);
        return;
      }
      else
        pwrbuf[j] = buffer[i];
      i++;
      j++;
    }
    power = atoi(pwrbuf);
    if (verbosity>=2)  printf ("pwr: %d ", power);
    j=0;
    while (buffer[i] == ' ') i++;
    while (i<lSize) {
      if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
        time[j] = '\0';
        i++;
        break;
      }
      else
        time[j] = buffer[i];
      i++;
      j++;
    }
    while (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n') i++;
    if (verbosity>=2) printf ("time: %s\n", time);
//    if (bssid[0] != '(') { // (not associated)
      curr = findApHT (aptable, bssid);
      if (curr != NULL) {
        curr->maxPwrLevel = power;
        strcpy(curr->maxPwrTime, time);
      }
//    }
  }
  free (buffer);
}

void readEnddevPowerFromFile (enddev *first, FILE *f) {
  enddev *curr;
  char mac[80];
  char pwrbuf[80];
  char time[80];
  char *buffer;
  int power;
  int result;
  long lSize;

  if (first == NULL) return;
  buffer = readFileToString(f, &lSize);
  long i=0;
  int j=0;
  while (i<lSize) {
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',') {
        mac[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        fprintf (stderr, "Error: unexpected EOL for mac %s\n", mac);
        return;
      }
      else
        mac[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("mac: %s ", mac);
    while (buffer[i] == ' ') i++;
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',')  {
        pwrbuf[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        fprintf (stderr, "Error: unexpected EOL for mac %s\n", mac);
        return;
      }
      else
        pwrbuf[j] = buffer[i];
      i++;
      j++;
    }
    power = atoi(pwrbuf);
    if (verbosity>=2) printf ("pwr: %d ", power);
    j=0;
    while (buffer[i] == ' ') i++;
    while (i<lSize) {
      if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
        time[j] = '\0';
        i++;
        break;
      }
      else
        time[j] = buffer[i];
      i++;
      j++;
    }
    while (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n') i++;
    if (verbosity>=2) printf ("time: %s\n", time);
//    curr = findEnddevByMAC (first, mac);
    curr = findStaHT (statable, mac);
    if (curr != NULL) {
//      printf("Found station %s\n", mac);
      curr->maxPwrLevel = power;
      strcpy(curr->maxPwrTime, time);
    } else {
      if (verbosity>=2) printf("findStaHT - %s - not found\n", mac);
    }
  }

  free (buffer);
}

// Prints last time displayed from a linked list of Enddevs (e) to a file (f)
void printEndDevicesDisplayedToFile (enddev *e, FILE *f) {
  int result;
  int i;
  enddev *curr = e;

  while (curr != NULL) {
    if (!isValidMacAddress(curr->station_mac)) {
      fprintf (stderr, "readEnddevDisplayedFromFile: discarding invalid mac %s\n", curr->station_mac);
      curr = curr->next;
      continue;
    }
    fprintf (f, "%s, %s, %s%s", curr->station_mac, curr->last_time_displayed, curr->essid, CRLF);
    if (verbosity >= 2) printf ("printEndDevicesDisplayedToFile: %s, %s, %s\n", curr->station_mac, curr->last_time_displayed, curr->essid);
    result = ferror (f);
    if (result) {
      printf ("printEndDevicesDisplayedToFile fprintf returned error: %d\n", result);
      return;
    }
    curr = curr->next;
  }
  for (i=0; i < extraStaCt; i++) {
    fprintf (f, "%s, %s, %s%s", extraSta[i].mac, extraSta[i].vendor, extraSta[i].essid, CRLF);
    if (verbosity >= 2) printf ("printEndDevicesDisplayedToFile EXTRA: %s, %s, %s\n", extraSta[i].mac, extraSta[i].vendor, extraSta[i].essid);
    result = ferror (f);
    if (result) {
      printf ("printEndDevicesDisplayedToFile fprintf returned error: %d\n", result);
      return;
    }
  }
  fprintf(f, "%s", CRLF);
}

void readEnddevDisplayedFromFile (enddev *first, FILE *f) {
  enddev *curr;
  char mac[80];
  char time[80];
  char essid[80];
  char *buffer;
  int power;
  int result;
  long lSize;

//  if (first == NULL) return;
  buffer = readFileToString(f, &lSize);
  long i=0;
  int j=0;
  int nLines=0;
  while (i<lSize) {
    if (buffer[i] == '\n')
      nLines++;
    i++;
  }
  if (verbosity >=2) printf ("readEnddevDisplayedFromFile: Allocating memory for extraSta\n");
  extraSta = (macdb*) malloc (sizeof(macdb) * nLines);
  i=0;
  while (i<lSize) {
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',') {
        mac[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        fprintf (stderr, "readEnddevDisplayedFromFile: Error: unexpected EOL for mac %s\n", mac);
        return;
      }
      else
        mac[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("readEnddevDisplayedFromFile: mac: %s ", mac);
//    while (buffer[i] == ' ') i++; // why is this here?
    j=0;
    int atEnd=0;
    while (buffer[i] == ' ') i++;
    while (i<lSize) {
      if (buffer[i] == '\r' || buffer[i] == '\n') {
        atEnd = 1;
      }
      if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
        time[j] = '\0';
        i++;
        break;
      }
      else
        time[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("time: %s\n", time);
    essid[0]='\0'; // possibly blank
    if (!atEnd) {
      // additional parameter: essid
      while (buffer[i] == ' ') i++;  // skip whitespace
      while (i<lSize) {
        if (j>=79) {
          essid[j]='\0';
          break; // might have essid > 80 chars
        }
        if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
          essid[j] = '\0';
          i++;
          break;
        }
        else
          essid[j] = buffer[i];
        i++;
        j++;
      }
    }
    while (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n') i++; // skip past additional whitespace
    int essidlen=strlen(essid);
//    if (verbosity>=2) printf ("essid: %s len: %d\n", essid, essidlen);
/*    {
      int k;
      for (k=0; buffer[k] != '\0'; k++) {
        printf("%c", charToHex(buffer[k]));
      }
      printf("\n");
    }
 */
    if (!isValidMacAddress(mac)) {
      fprintf (stderr, "readEnddevDisplayedFromFile: got invalid mac %s\n", mac);
      continue;
    }
//    curr = findEnddevByMAC (first, mac);
    curr = findStaHT (statable, mac);
    if (curr != NULL) {
//      printf("found %s\n", mac);
      strcpy(curr->last_time_displayed, time);
      if (strlen(essid) > 2) {
//        printf ("%s LEN: %d\n", essid, strlen(essid);
        strcpy(curr->essid, essid);
      }
//      printf ("readEnddevDisplayedFromFile: Added LTD (%s) for %s\n", time, mac);
    } else {
      strcpy(extraSta[extraStaCt].mac, mac);
      strcpy(extraSta[extraStaCt].vendor, time);
      strcpy(extraSta[extraStaCt].essid, essid);  // I don't think this matters
      extraStaCt++;
      if (verbosity >= 2) fprintf (stdout, "Added extra station LTD: %s MAC: %s\n", time, mac);
    }
  }
  if (verbosity >= 2) printf ("readEnddevDisplayedFromFile: End of function\n");
}

gps *readGPSFile (ap *firstap, enddev *firsted, FILE *f) {
  gps *g, *g1, *gprev;
  int result;

  gprev = g = g1 = (gps *) malloc (sizeof(gps));

  while (1) {
    result = fscanf (f, "%d-%d-%d %d:%d:%d, %lf, %lf\r\n", &(g->dt.year), &(g->dt.month), &(g->dt.day), &(g->dt.hour), &(g->dt.minute), &(g->dt.second), &(g->lat), &(g->lon));
    if (result == EOF) {
      gprev->next = NULL;
      free(g);
      return g1;
    }
    g->next = (gps *) malloc (sizeof(gps));
    gprev = g;
    g = g->next;
  }
  return g1;
}

void addGPSInfo (ap *firstap, enddev *firsted, gps *firstg) {
  ap *currap = firstap;
  enddev *curred = firsted;
  gps *g = firstg;
  int result;
  int badtime = 0;

  while (currap != NULL) {
//    printf ("Read AP GPS info for: %s\n", currap->bssid);
    result = strToTime (&(currap->mpTime), currap->maxPwrTime);
    if (result == EOF) {
      printf ("Error reading GPS file\n");
      printf ("Max power time: %s\n", currap->maxPwrTime);
      return;
    }
    if (compareDates (&(currap->mpTime), &(g->dt)) == -1) {
      // Skip this AP, too old
      currap = currap->next;
      continue;
    }

    badtime = 0;
    while (compareDates (&(currap->mpTime), &(g->dt)) == 1) {
      // If compareDates returns 0 or -1, the current AP's date is less than or equal to
      // the date in the GPS file we are checking against.
//      printf ("Is %d:%d:%d > %d:%d:%d?\n", currap->mpTime.hour, currap->mpTime.minute, currap->mpTime.second, g->dt.hour, g->dt.minute, g->dt.second);
      g = g->next;
      if (g == NULL) {
        // Date not in range
        badtime = 1;
        break;
      }
    }
    currap->lat = badtime ? 0 : g->lat;
    currap->lon = badtime ? 0 : g->lon;
    g = firstg;
    currap = currap->next;
  }
  while (curred != NULL) {
//    printf ("Reading Station info for: %s\n", curred->station_mac);
    result = strToTime (&(curred->mpTime), curred->maxPwrTime);
    if (result == EOF) {
      printf ("Error reading station info for %s\n", curred->station_mac);
      printf ("Max power time: %s\n", curred->maxPwrTime);
      return;
    }
    if (compareDates (&(curred->mpTime), &(g->dt)) == -1) {
      // Skip this end device, too old
      curred = curred->next;
      continue;
    }

    badtime = 0;
    while (compareDates (&(curred->mpTime), &(g->dt)) == 1) {
      g = g->next;
      if (g == NULL) {
        // Date not in range
        badtime = 1;
        break;
      }
    }
    curred->lat = badtime ? 0 : g->lat;
    curred->lon = badtime ? 0 : g->lon;
    g = firstg;
    curred = curred->next;
  }
}

// Prints a single AP (a) to a file (f)
void printAPToFileKML (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (a->lat == 0.0) return; // no GPS data
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;
  fprintf(f, "<Placemark>%s"
    "<name>%s (%s)</name>%s"
    "<description>%s", CRLF, strcmp(a->desc, "") == 0 ? a->essid : a->desc, str_replace(a->vendor, '&', ' '), CRLF, CRLF);
  fprintf (f, "Description: %s%s", a->desc, CRLF);
  fprintf (f, "BSSID: %s%s", a->bssid, CRLF);
  fprintf (f, "Vendor: %s%s", str_replace(a->vendor, '&', ' '), CRLF);
  fprintf (f, "First time seen: %s%s", a->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", a->last_time_seen, CRLF);
  fprintf (f, "Channel: %s%s", a->channel, CRLF);
  fprintf (f, "Speed: %s%s", a->speed, CRLF);
  fprintf (f, "Privacy: %s%s", a->privacy, CRLF);
  fprintf (f, "Cipher: %s%s", a->cipher, CRLF);
  fprintf (f, "Authentication: %s%s", a->authentication, CRLF);
  fprintf (f, "Power: %d%s", a->power, CRLF);
  fprintf (f, "Previous Power: %d%s", a->oldPower, CRLF);
  fprintf (f, "Beacons: %s%s", a->beacons, CRLF);
  fprintf (f, "IVs: %s%s", a->ivs, CRLF);
  fprintf (f, "LAN IP: %s%s", a->lan_ip, CRLF);
  fprintf (f, "ID-length: %s%s", a->id_length, CRLF);
  fprintf (f, "ESSID: %s%s", a->essid, CRLF);
  fprintf (f, "Key: %s%s", a->key, CRLF);
  fprintf (f, "Max Power: %d%s", a->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", a->maxPwrTime, CRLF);
  fprintf (f, "IP Address: %s%s", a->ip, CRLF);
  fprintf (f, "File: %s%s%s", a->fileName, CRLF, CRLF);

  fprintf (f, "</description>%s"
    "<Point>%s"
      "<coordinates>%lf,%lf</coordinates>%s"
    "</Point>%s"
  "</Placemark>%s", CRLF, CRLF, a->lon, a->lat, CRLF, CRLF, CRLF);

}

// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileKML (enddev *e, FILE *f) {
  int powerDelta = e->power - e->oldPower;
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (e->lat == 0.0) return; // no GPS data
  if (onlyShowKnown && strcmp(e->desc, "") == 0) {
    if (verbosity) printf ("Skipping station: %s\n", e->station_mac); 
    return;
  }
  if (deltaSpecified) {
    if (e->oldPower >= -1 || powerDelta <= minPowerDelta) return;
  }
  fprintf(f, "<Placemark>%s"
    "<name>%s (%s)</name>%s"
    "<description>%s", CRLF, strcmp(e->desc, "") == 0 ? e->station_mac : e->desc, str_replace(e->vendor, '&', ' '), CRLF, CRLF);
  fprintf (f, "Description: %s%s", e->desc, CRLF);
  fprintf (f, "Station MAC: %s%s", e->station_mac, CRLF);
  fprintf (f, "Vendor: %s%s", str_replace(e->vendor, '&', ' '), CRLF);
  fprintf (f, "First time seen: %s%s", e->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", e->last_time_seen, CRLF);
  fprintf (f, "Power: %d%s", e->power, CRLF);
  fprintf (f, "Previous Power: %d%s", e->oldPower, CRLF);
  fprintf (f, "Packet count: %s%s", e->packets, CRLF);
  fprintf (f, "BSSID: %s%s", e->bssid, CRLF);
  fprintf (f, "ESSID: %s%s", e->essid, CRLF);
  fprintf (f, "Probed ESSIDs: %s%s", e->probed_essids, CRLF);
  fprintf (f, "Max Power: %d%s", e->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", e->maxPwrTime, CRLF);
  fprintf (f, "IP address: %s%s", e->ip, CRLF);
  fprintf (f, "File %s%s%s", e->fileName, CRLF, CRLF);
  fprintf (f, "</description>%s"
    "<Point>%s"
      "<coordinates>%lf,%lf</coordinates>%s"
    "</Point>%s"
  "</Placemark>%s", CRLF, CRLF, e->lon, e->lat, CRLF, CRLF, CRLF);
}

// Prints a single AP (a) to a file (f)
void printAPToFileHTML (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;
  // If it's been less than MINTIME, return
  if (timeMin && compareToNow(a->last_time_seen, MINTIME) < 0) return;
  // If it's been more than MAXTIME, return
  if (timeMax && compareToNow(a->last_time_seen, MAXTIME) > 0) return;

  fprintf (f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
    "<td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%s",
    a->bssid, a->vendor, a->first_time_seen, a->last_time_seen, a->prev_last_time_seen, a->channel, a->speed, a->privacy, a->cipher,
    a->authentication, a->power, a->beacons, a->ivs, a->lan_ip, a->id_length, a->essid, a->key, a->desc, a->ip,
    CRLF);
}
/*
// Prints all of the APs in the linked list (a) to a file (f)
void printAPsToFileHTML (ap *a, FILE *f) {
  int result;
  int i;
  ap *currAp = a;

  if (a == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  if (onlyAddNew) {
    if (a->new) printAPToFileHTML (a, f);
  } else if (onlyAddOld) {
    if (a->old) printAPToFileHTML(a, f);
  } else {
    printAPToFileHTML (a, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printAPsToFileHTML fprintf returned error: %d\n", result);
    return;
  }
  printAPsToFileHTML (a->next, f);
}
*/

// Prints a single Enddev (e) to a file (f)
// http://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
void printEndDeviceToFileHTML (enddev *e, FILE *f) {
  datetime delta, d1, d2;
  char deltastr[80];
  strToTime(&d1, e->last_time_seen);
  strToTime(&d2, e->first_time_seen);
//  strToTime(&d2, e->prev_last_time_seen);
  dateDiff(&delta, &d1, &d2);
  timeToStr(&delta, deltastr);

  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (onlyShowKnown && strcmp(e->desc, "") == 0) return;

  // If it's been less than MINTIME, return
  if (timeMin && compareToNow(e->last_time_displayed, MINTIME) < 0) return;
  // If it's been more than MAXTIME, return
  if (timeMax && compareToNow(e->last_time_displayed, MAXTIME) > 0) return;
  fprintf (f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%s", e->station_mac, e->vendor, e->first_time_seen,
    e->last_time_seen, deltastr, e->power, e->packets, e->bssid, e->channel, e->essid, e->probed_essids, e->desc, e->ip, CRLF);
}
/*
// Prints a linked list of Enddevs (e) to a file (f)
void printEndDevicesToFileHTML (enddev *e, FILE *f) {
  int result;
  int i;
  enddev *curr = e;

  if (e == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  if (onlyAddNew) {
    if (e->new) printEndDeviceToFileHTML (e, f);
  } else if (onlyAddOld) {
    if (e->old) printEndDeviceToFileHTML (e, f);
  } else {
    printEndDeviceToFileHTML (e, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileHTML fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesToFileHTML (e->next, f);
}
*/

// Prints a single AP (a) to a file (f)
void printAPToFileCSV (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  fprintf (f, "%s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s%s",
    a->bssid, a->first_time_seen, a->last_time_seen, a->channel, a->speed, a->privacy, a->cipher,
    a->authentication, a->power, a->beacons, a->ivs, a->lan_ip, a->id_length, a->essid, a->key, CRLF);
}

// Prints all of the APs in the linked list (a) to a file (f)
// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileCSV (enddev *e, FILE *f) {
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  fprintf (f, "%s, %s, %s, %d, %s, %s, %s%s", e->station_mac, e->first_time_seen,
    e->last_time_seen, e->power, e->packets, e->bssid, e->probed_essids, CRLF);
}

// Prints a single ap (a) to a file (f)
void printAPToFileText (ap *a, FILE *f) {
  int powerDelta = a->power - a->oldPower;
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;
  // If it's been less than MINTIME, return
  if (timeMin && compareToNow(a->last_time_seen, MINTIME) < 0) return;
  // If it's been more than MAXTIME, return
  if (timeMax && compareToNow(a->last_time_seen, MAXTIME) > 0) return;

  if (deltaSpecified) {
    if (a->oldPower >= -1 || powerDelta <= minPowerDelta) return;
    // We found something, ring a bell
//    printf ("\a");
  }

  if (text_brief) {
    fprintf (f, "%s AP:  %s ESSID: %s PWR: %d DESC: %s VEN: %s%s", a->last_time_seen, a->bssid, a->essid, a->power, a->desc, a->vendor, CRLF);
    return;
  }

  fprintf (f, "BSSID: %s%s", a->bssid, CRLF);
  fprintf (f, "Vendor: %s%s", a->vendor, CRLF);
  fprintf (f, "First time seen: %s%s", a->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", a->last_time_seen, CRLF);
  fprintf (f, "Previous last time seen: %s%s", a->prev_last_time_seen, CRLF);
//  fprintf (f, "Since previous LTS: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
  fprintf (f, "Channel: %s%s", a->channel, CRLF);
  fprintf (f, "Speed: %s%s", a->speed, CRLF);
  fprintf (f, "Privacy: %s%s", a->privacy, CRLF);
  fprintf (f, "Cipher: %s%s", a->cipher, CRLF);
  fprintf (f, "Authentication: %s%s", a->authentication, CRLF);
  fprintf (f, "Power: %d%s", a->power, CRLF);
  fprintf (f, "Previous Power: %d%s", a->oldPower, CRLF);
  fprintf (f, "Beacons: %s%s", a->beacons, CRLF);
  fprintf (f, "IVs: %s%s", a->ivs, CRLF);
  fprintf (f, "LAN IP: %s%s", a->lan_ip, CRLF);
  fprintf (f, "ID-length: %s%s", a->id_length, CRLF);
  fprintf (f, "ESSID: %s%s", a->essid, CRLF);
  fprintf (f, "Key: %s%s", a->key, CRLF);
  fprintf (f, "Max Power: %d%s", a->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", a->maxPwrTime, CRLF);
  fprintf (f, "Latitude: %lf%s", a->lat, CRLF);
  fprintf (f, "Longitude: %lf%s", a->lon, CRLF);
  fprintf (f, "File: %s%s", a->fileName, CRLF);
  fprintf (f, "IP Address: %s%s", a->ip, CRLF);
  fprintf (f, "Description: %s%s%s", a->desc, CRLF, CRLF);
}
/*
// Prints a linked list of APs (a) to a file (f)
void printAPsToFileText (ap *a, FILE *f) {
  int i, result;
  ap *currAp = a;

  if (a == NULL) return;
  if (onlyAddNew) {
    if (a->new) printAPToFileText (a, f);
  } else if (onlyAddOld) {
    if (a->old) printAPToFileText (a, f);
  } else {
    printAPToFileText (a, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printAPsToFileText fprintf returned error: %d\n", result);
    return;
  }
  printAPsToFileText (a->next, f);
}
*/
// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileText (enddev *e, FILE *f) {
  int powerDelta = e->power - e->oldPower;
  char descbuf[256];
  int skip = 0;
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (!isValidMacAddress(e->station_mac)) {
    fprintf(stderr,"printEndDeviceToFileText: Discarding invalid MAC: %s\n", e->station_mac);
    return;
  }
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (onlyShowKnown && strcmp(e->desc, "") == 0) return;

  // Alert if this device has gone away
  // Not seen for exactly 31 to 40 seconds
//  if (compareToNow (e->last_time_displayed, "0000-00-00 00:00:30") > 0 && compareToNow (e->last_time_displayed, "0000-00-00 00:00:40") <= 0) {
      // if strToTime is successful and last_time_displayed was within the last minute
//      fprintf(stdout, "Station %s (%s) went away. LTD: %s\n", e->station_mac, e->desc, e->last_time_displayed);
//  }

  if (deltaSpecified) {
    if (e->oldPower >= -1 || powerDelta <= minPowerDelta) {
//      printf("%s - Not printing due to delta: %s %s\n", e->last_time_seen, e->station_mac, e->desc);
      skip = 1;
    }
  }

  char ltd_old[80];
  strcpy(ltd_old, e->last_time_displayed);
  char currtime[26];
  time_t timer;
  struct tm* tm_info;

  time(&timer);
  tm_info = localtime(&timer);
  strftime(currtime, 26, "%Y-%m-%d %H:%M:%S", tm_info);
  
  // If we recently saw this device, set last time displayed to now, even if MINTIME/MAXTIME not met.
  // May not always be desirable, but the goal is to prevent devices that
  // remain in range from spamming the screen.
  if (!skip && compareToNow (e->last_time_seen, "0000-00-00 00:00:30") < 0) {
    // If last_time_seen is within the last 30 seconds
    strcpy(e->last_time_displayed, currtime);
    if (verbosity >= 2) fprintf(stdout, "Updating LTD for %s to %s\n", e->station_mac, e->last_time_displayed);
  }

  // If for some reason, ltd_old is after last_time_seen, return (prevents spamming old data)
  datetime d1, d2;
  if (!strToTime (&d1, e->last_time_seen)) return; // return if strToTime fails
  if (!strToTime (&d2, ltd_old)) return;

  // If it's been less than MINTIME, return
  if ( timeMin && (compareToNow(ltd_old, MINTIME) <= 0 || compareDates(&d1, &d2) < 0 ) ) {
//    printf("%s - Not printing due to MINTIME: %s DESC: %s LTD:%s\n", e->last_time_seen, e->station_mac, e->desc, ltd_old);
    return;
  }
  // If it's been more than MAXTIME, return
//  printf ("%s ", e->station_mac); // print mac address for debugging compareToNow()
  if (timeMax && compareToNow(ltd_old, MAXTIME) > 0) {
//    printf("%s - Not printing due to MAXTIME: %s DESC: %s LTD:%s\n", e->last_time_seen, e->station_mac, e->desc, ltd_old);
    return;
  }

  if (skip) return;

  // Make last_time_displayed the current time
  strcpy(e->last_time_displayed, currtime);

//  play_sound("heart.mp3");

//  if (verbosity >= 2) printf ("Sending UDP segment...");
//  sprintf(descbuf, "STA: %s (%s) ESSID: %s PWR: %d DESC: %s\n", e->station_mac, e->vendor, e->essid, e->power, e->desc);
//  sprintf(descbuf, "%s", e->desc);
//  if (remoteserver)
//    send_info_udp(remoteserver, remoteport, descbuf);

  if (text_brief) {
    datetime delta, d1, d2;
    char nowstr[26];
    char ftsstr[26];
    char ltsstr[26];
    char ltdstr[26];
    getNowStr(nowstr);
    /* time since first time seen */
    strToTime(&d1, nowstr);
    strToTime(&d2, e->first_time_seen);
    dateDiff(&delta, &d1, &d2);
    dateHuman(&delta, ftsstr);
    /* time since last time seen */
    strToTime(&d1, nowstr);
    strToTime(&d2, e->last_time_seen);
    dateDiff(&delta, &d1, &d2);
    dateHuman(&delta, ltsstr);
    /* time since last time displayed */
    strToTime(&d1, nowstr);
    strToTime(&d2, ltd_old);
    datetime zerodate;
    strToTime(&zerodate, "0000-00-00 00:00:00");
    if(compareDates(&zerodate, &d2) == 0) {
      strcpy(ltdstr, "new");
    } else {
      dateDiff(&delta, &d1, &d2);
      dateHumanLong(&delta, ltdstr);
    }
//    fprintf (f, "%s STA: %s CH%s ESSID: %s PWR: %d DESC: %s VEN: %s%s", e->last_time_seen, e->station_mac, e->channel, e->essid, e->power+100, e->desc, e->vendor, CRLF);
//    fprintf (f, "LTS: %s LTD: %s FtL: %s STA: %s CH%s ESSID: %s PWR: %d DESC: %s VEN: %s%s", e->last_time_seen, ltd_old, deltastr, e->station_mac, e->channel, e->essid, e->power+100, e->desc, e->vendor, CRLF);
//    e->channel[4] = '\0';
    fprintf (f, "%s,%s,%s,%s,%s,%s,%d,%s,%s%s", nowstr, ltsstr, ltdstr, e->station_mac, e->channel, e->essid, e->power+100, e->desc, e->vendor, CRLF);
    if (remoteserver) {
      char descbuf[80];
/*
      if (strcmp(e->desc, "") != 0)
        strcpy(descbuf, e->essid);
      else
        strcpy(descbuf, e->desc);
      if (strcmp(descbuf, "") != 0) {
*/
      if (strcmp(e->desc, "") != 0) {
        bzero(descbuf, 80);
        strcat(descbuf, e->desc);
        strcat(descbuf, ", ");
        strcat(descbuf, ltdstr);
        if (remoteserver)
          send_info_udp(remoteserver, remoteport, descbuf);
      }
    }
    return;
  }
  fprintf (f, "Station MAC: %s%s", e->station_mac, CRLF);
  fprintf (f, "Vendor: %s%s", e->vendor, CRLF);
  fprintf (f, "First time seen: %s%s", e->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", e->last_time_seen, CRLF);
  fprintf (f, "Previous last time seen: %s%s", e->prev_last_time_seen, CRLF);
//  fprintf (f, "Since previous LTS: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
  fprintf (f, "Power: %d%s", e->power, CRLF);
  fprintf (f, "Previous Power: %d%s", e->oldPower, CRLF);
  fprintf (f, "Packet count: %s%s", e->packets, CRLF);
  fprintf (f, "BSSID: %s%s", e->bssid, CRLF);
  fprintf (f, "ESSID: %s%s", e->essid, CRLF);
  fprintf (f, "Channel: %s%s", e->channel, CRLF);
  fprintf (f, "Probed ESSIDs: %s%s", e->probed_essids, CRLF);
  fprintf (f, "Max Power: %d%s", e->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", e->maxPwrTime, CRLF);
  fprintf (f, "Latitude: %lf%s", e->lat, CRLF);
  fprintf (f, "Longitude: %lf%s", e->lon, CRLF);
  fprintf (f, "File: %s%s", e->fileName, CRLF);
  fprintf (f, "IP Address: %s%s", e->ip, CRLF);
  fprintf (f, "Description: %s%s%s", e->desc, CRLF, CRLF);
}

/*
// Prints a linked list of Enddevs (e) to a file (f)
void printEndDevicesToFileText (enddev *e, FILE *f) {
  int i, result;
  enddev *curr = e;

  if (e == NULL) return;
  if (onlyAddNew) {
    if (e->new) printEndDeviceToFileText (e, f);
  } else if (onlyAddOld) {
    if (e->old) printEndDeviceToFileText (e, f);
  } else {
    printEndDeviceToFileText (e, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileText fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesToFileText (e->next, f);
}
*/

// Prints all of the APs in the linked list (a) to a file (f)
void printAPsToFileRec (ap *a) {
  int result;
  int i;
  int skip = 1;
  ap *curr = a;
  ap **ap_arr = (ap **) malloc(ap_count * sizeof(ap*));

  for (i=0; i < ap_count; i++) {
    if (curr == NULL) {
      ap_arr[i] = NULL;
//      break; // should not reach this but just in case...
    } else{
       ap_arr[i] = curr;
      curr = curr->next;
    }
  }
  switch (sortBy) {
  case 0:
    qsort(ap_arr, ap_count, sizeof(ap*), &compareApByPwr);
    break;
  case FIRSTSEEN:
    qsort(ap_arr, ap_count, sizeof(ap*), &compareApFirstseen);
    break;
  case LASTSEEN:
    qsort(ap_arr, ap_count, sizeof(ap*), &compareApLastseen);
    break;
  }

  for (i=0; i < ap_count; i++) {
    curr = ap_arr[i];

    if (curr == NULL) {
      break;
    }

    skip = 1;
    if (onlyAddNew) {
      if (curr->new) {
        skip = 0;
//        printf("AP is new: %s\n", curr->bssid);
      }
    } else if (onlyAddOld) {
      if (curr->old) {
        skip = 0;
//        printf("AP is old: %s\n", curr->bssid);
      }
    } else {
      skip = 0;
//      printf("OnlyAddNew and OnlyAddOld are off\n");
    }

    if (!skip) {
      printAPToFileCSV (curr, csvFile);
      printAPToFileText (curr, textFile);
      printAPToFileHTML (curr, htmlFile);
      if (kmlFile) printAPToFileKML (curr, kmlFile);
    }
  }
  fprintf(csvFile, "%s", CRLF);
/*
  result = ferror (f);
  if (result) {
    printf ("printAPsToFileCSV fprintf returned error: %d\n", result);
    return;
  }
 */
//  printAPsToFileRec (a->next);
}

// Prints a linked list of Enddevs (e) to files (text, html, csv)
void printEndDevicesToFileRec (enddev *e) {
  int result;
  int i;
  int skip = 1;
  enddev *curr = e;
  enddev **sta_arr = (enddev **) malloc(sta_count * sizeof(enddev*));

  for (i=0; i < sta_count; i++) {
    if (curr == NULL) {
      sta_arr[i] = NULL;
      // should not get here, but just in case...
      if (verbosity >= 2) printf("Warning: got a null station!\n");
    } else {
      sta_arr[i] = curr;
      if (verbosity >= 2) printf("Added station %s\n", curr->station_mac);
      curr = curr->next;
    }
  }
  switch (sortBy) {
  case 0:
    qsort(sta_arr, sta_count, sizeof(enddev*), &compareStaByPwr);
    break;
  case FIRSTSEEN:
    qsort(sta_arr, sta_count, sizeof(enddev*), &compareStaFirstseen);
    break;
  case LASTSEEN:
    qsort(sta_arr, sta_count, sizeof(enddev*), &compareStaLastseen); 
    break;
  }

  for (i=0; i < sta_count; i++) {
    curr = sta_arr[i];
    if (curr == NULL) {
      break;
    }
    skip = 1;
//    printf("i = %d/%d\n", i, sta_count);
//    printf("next station (%d): %s\n", i, curr->station_mac);
    if (onlyAddNew) {
      if (curr->new) skip = 0;
    } else if (onlyAddOld) {
      if (curr->old) skip = 0;
    } else {
      skip = 0;
    }

    if (!skip) {
      if (verbosity >= 2) printf("Printing to csv/text/html station: %s Pwr: %d\n", curr->station_mac, curr->power);
      if (verbosity >= 2) printf("Printing station to csv file.\n");
      printEndDeviceToFileCSV (curr, csvFile);
      if (verbosity >= 2) printf("Printing station to text file.\n");
      printEndDeviceToFileText (curr, textFile);
      if (verbosity >= 2) printf("Printing station to html file.\n");
      printEndDeviceToFileHTML (curr, htmlFile);
      if (verbosity >= 2) printf("Printing %s to KML file\n", curr->station_mac);
      if (kmlFile) printEndDeviceToFileKML (curr, kmlFile);
    }
  }
  fprintf(csvFile, "%s", CRLF);
  free(sta_arr); 

/*
  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileCSV fprintf returned error: %d\n", result);
    return;
  }
*/
//  printEndDevicesToFileRec (e->next);  // not using recursion anymore
}

int compareMacDbItems ( const void *p1, const void *p2 ) {
  const macdb *e1 = (macdb*) p1;
  const macdb *e2 = (macdb*) p2;

  return strcmp (e1->mac, e2->mac);
}

// Read the vendor MAC address database into an array
// Output: sets globals mac_database and mac_db_sz
void readMacDB (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor, *macfile;
  macdb *curr_node;
  int i, ven;
  int lines=0;

  pFile = fopen (fileName, "r");
  if (pFile == NULL) {
   fprintf (stderr, "readMacDB - Error opening file: %s\n", fileName);
   exit(1);
  }

  // Count how many vendors there are
  macfile = readFileToString(pFile, &lSize);
  for (i=0; i < lSize; i++) {
    if(macfile[i] == '\n') lines++;
  }
//  printf("Got %d vendors\n", lines);
  mac_db_sz = lines;

  rewind(pFile);
  mac_database = (macdb *) malloc (lines * sizeof(macdb));

  for (ven=0; ven < lines; ven++) {
    if (fgets (buffer, 120, pFile) == NULL) {
      break;
    }
    curr_node = mac_database + ven;
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 8);
    mac[8] = '\0';
    for (i=0; i < 8; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    memcpy (vendor, buffer + 18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }
//      printf ("Got ven: %s mac: %s\n", vendor, mac);
  }
  qsort(mac_database, lines, sizeof(macdb), &compareMacDbItems);
}

// Reads a CSV list of known MAC addresses (user-generated)
// So they can be placed next to the AP/station
// "Vendor" in this case is the user-generated comment
// Output: sets globals known_macs and known_macs_sz
void readKnownMacs (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor, *macfile;
  macdb *curr_node;
  int i, ven;
  int lines=0;

  pFile = fopen (fileName, "r");
  if (pFile == NULL) {
   fprintf (stderr, "readKnownMacs - Error opening file: %s\n", fileName);
   exit(1);
  }

  // Count how many vendors there are
  macfile = readFileToString(pFile, &lSize);
  for (i=0; i < lSize; i++) {
    if(macfile[i] == '\n') lines++;
  }
//  printf("Got %d vendors\n", lines);
  known_macs_sz = lines;

  rewind(pFile);
  known_macs = (macdb *) malloc (lines * sizeof(macdb));

  for (ven=0; ven < lines; ven++) {
    if (fgets (buffer, 120, pFile) == NULL) {
      break;
    }
    curr_node = known_macs + ven;
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 17); // 17 mac address characters
    mac[17] = '\0';
    for (i=0; i < 17; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    // convert to upper case
    for (i=0; i<17; i++) {
      if (mac[i] >= 97 && mac[i] <= 122) {
        mac[i] -= 32;
      }
    }
    memcpy (vendor, buffer + 18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }
//      printf ("Adding DESC: %s MAC: %s\n", vendor, mac);
  }
  qsort(known_macs, lines, sizeof(macdb), &compareMacDbItems);
}

// Reads a CSV list of known IP addresses (script-generated)
// So they can be placed next to the AP/station
// "Vendor" in this case is the IP address
void readKnownIPs (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor;
  macdb *curr_node;
  int i;

  pFile = fopen (fileName, "r");

  if (pFile == NULL) {
   printf ("readKnownMacs - Error opening file: %s\n", fileName);
   exit(1);
  }

  while (fgets (buffer, 120, pFile) != NULL) {
    if (known_ips == NULL) {
      known_ips = (macdb *) malloc (sizeof(macdb));
      known_ips->next = NULL;
      curr_node = known_ips;
    } else {
      curr_node->next = (macdb *) malloc (sizeof(macdb));
      curr_node = curr_node->next;
      curr_node->next = NULL;
    }
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 17); // not sure about 17 (mac address characters)
    mac[17] = '\0';
    for (i=0; i < 8; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    for (i=0; i<17; i++) {
      if (mac[i] >= 97 && mac[i] <= 122) {
        mac[i] -= 32; // convert to upper case
      }
    }
    memcpy (vendor, buffer+18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }

//    printf ("Added %s - %s\n", mac, vendor);
  }
}

// Reads a CSV file (fileName)
// Inserts the APs into a linked list of APs (firstAp)
// Inserts the Enddevs into a linked list of Enddevs (firstEnddev)
// Returns a devset with the addresses of the first AP and Devset
// because the values passed in will be NULL if this is the first file read
devset readCSVFile (char * fileName, ap *firstAp, enddev *firstEnddev, const int lastFile) {
  FILE *pFile;
  long i=0, j=0, k=0;
  long lSize;
  char *buffer;
  char mac[9];
  char power[5];
  char currWord[80];
  char description[16][80];
  char first_time_seen[80];
  int keepDate;
  size_t result;
  ap *currAp = NULL;
  ap *lastAp = firstAp;
  ap *tempAp = NULL;
  enddev *currEnddev = NULL;
  enddev *lastEnddev = firstEnddev;
  enddev *tempEnddev = NULL;
  devset dset;

  pFile = fopen (fileName, "r");

  if (pFile == NULL) {
   printf ("readCSVFile - Error opening file: %s\n", fileName);
   exit(1);
  }

  if (lastAp != NULL) while (lastAp->next != NULL) lastAp = lastAp->next;
  if (lastEnddev != NULL) while (lastEnddev->next != NULL) lastEnddev = lastEnddev->next;
  
  // obtain file size
  fseek (pFile, 0, SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  // allocate memory to contain the whole file
  buffer = (char*) malloc(sizeof(char) * lSize);
  if (buffer == NULL) {
    fputs ("Memory error\n", stderr);
    exit(2);
  }

  // copy the file into the buffer
  result = fread (buffer, 1, lSize, pFile);
  if (result != lSize) {
    fputs ("Reading error\n", stderr);
    exit(3);
  }
 
  // Skip the first two lines
  j=0;
  for (i=0; i < lSize-1; i++) {
    if (buffer[i] == '\n') j++;
    if (j == 2) {
      i++;
      break;
    }
  }

  if (verbosity >= 2) printf ("Processing %s\n", fileName);
  // Read the list of aps
  while (i < lSize-1) {
    //Check if we are at the end of the ap list
    if (buffer[i] == '\n') {
      i++;
      break;
    } else if (buffer[i]== '\r' && buffer[i+1] == '\n') {
      i += 2;
      break;
    }
    // Read the next AP
    i = getWord (currWord, buffer, i, lSize);
    keepDate = 0;
    if (firstAp == NULL) {
      firstAp = (ap *) malloc (sizeof(ap));
      firstAp->next = NULL;
      firstAp->new = lastFile ? 1 : 0;
      firstAp->old = 0;
      firstAp->maxPwrLevel = -100;
      firstAp->prev_last_time_seen[0] = '\0';
      strcpy(firstAp->last_time_displayed, "0000-00-00 00:00:00");
      bzero(firstAp->maxPwrTime, 80);
      firstAp->lat = firstAp->lon = 0.0;
      lastAp = currAp = firstAp;
      ap_count++;
    } else {
//      currAp = findApByBSSID (firstAp, currWord);
        currAp = findApHT (aptable, currWord);
      if (currAp == NULL) {
        currAp = (ap *) malloc (sizeof(ap));
        currAp->next = NULL;
        currAp->new = lastFile ? 1 : 0;
        currAp->old = 0;
        currAp->prev_last_time_seen[0] = '\0';
        strcpy(currAp->last_time_displayed, "0000-00-00 00:00:00");
        currAp->maxPwrLevel = -100;
        bzero(currAp->maxPwrTime, 80);
        currAp->lat = currAp->lon = 0.0;
        lastAp->next = currAp;
        lastAp = currAp;
        ap_count++;
      } else {
        currAp->new = 0;
        currAp->old = lastFile ? 1 : 0;
        strcpy(first_time_seen, currAp->first_time_seen);
        keepDate = 1;
      }
    }

    strcpy (currAp->bssid, currWord);
    memcpy (mac, currAp->bssid, 8);
    mac[8] = '\0';
    strcpy (currAp->vendor, findVendorByMACBin (mac_database, mac_db_sz, mac));
    // "Vendor" is actually the description in this case
    strcpy (currAp->desc, findVendorByMACBin (known_macs, known_macs_sz, currAp->bssid));
    // Do the same for the IP address
    strcpy (currAp->ip, findVendorByMAC (known_ips, currAp->bssid));
    i = getWord (currAp->first_time_seen, buffer, i, lSize);
    if (keepDate) strcpy(currAp->first_time_seen, first_time_seen);
    i = getWord (currAp->last_time_seen, buffer, i, lSize);
    if (!lastFile) strcpy(currAp->prev_last_time_seen, currAp->last_time_seen);
    i = getWord (currAp->channel, buffer, i, lSize);
    if (strlen(currAp->channel) > 3) {
      fprintf(stderr, "Malformed channel parsing: %s\n", currAp->channel);
      strcpy(currAp->channel, "ERR");
    }
    i = getWord (currAp->speed, buffer, i, lSize);
    i = getWord (currAp->privacy, buffer, i, lSize);
    i = getWord (currAp->cipher, buffer, i, lSize);
    i = getWord (currAp->authentication, buffer, i, lSize);
    i = getWord (power, buffer, i, lSize);
    currAp->oldPower = 0;
    if (currAp->old) currAp->oldPower = currAp->power;
    currAp->power = atoi(power);
    i = getWord (currAp->beacons, buffer, i, lSize);
    i = getWord (currAp->ivs, buffer, i, lSize);
    i = getWord (currAp->lan_ip, buffer, i, lSize);
    i = getWord (currAp->id_length, buffer, i, lSize);
    i = getEssid (currAp->essid, buffer, i, lSize);
    i = getWord (currAp->key, buffer, i, lSize);
    strcpy (currAp->fileName, fileName);
    // I dont actually use the time1 and time2 for anything yet.
    memcpy(&(currAp->prvtime2), &(currAp->time2), sizeof(datetime));
    sscanf (currAp->first_time_seen, "%d-%d-%d %d:%d:%d", 
      &(currAp->time1.year),
      &(currAp->time1.month),
      &(currAp->time1.day),
      &(currAp->time1.hour),
      &(currAp->time1.minute),
      &(currAp->time1.second));
    sscanf (currAp->last_time_seen, "%d-%d-%d %d:%d:%d",
      &(currAp->time2.year),
      &(currAp->time2.month),
      &(currAp->time2.day),
      &(currAp->time2.hour),
      &(currAp->time2.minute),
      &(currAp->time2.second));
    if (currAp->power > currAp->maxPwrLevel && currAp->power < -1) {
      currAp->maxPwrLevel = currAp->power;
      strcpy(currAp->maxPwrTime, currAp->last_time_seen);
    }
    if (strcmp(currAp->maxPwrTime, "") == 0) strcpy(currAp->maxPwrTime, currAp->last_time_seen);
    if (findApHT (aptable, currAp->bssid) == NULL)  {
      if (addApToHT(aptable, currAp) == -1) {// Add the AP to the hash table
        fprintf(stderr, "Exiting due to malformed file\n");
        exit(1); // If file is malformed, exit and crash
      }
    }
    if (verbosity >= 2) printf("added ap: %s\n", currAp->bssid);
  }

  // Skip the description line
  while (i < lSize) {
    if (buffer[i] == '\n') {
      i++; break;
    }
    i++;
  }

  // Read the end devices
  while (i < lSize) {
    //Check if we are at the end of the end device list
    if (buffer[i] == '\n') {
      i++;
      break;
    } else if (buffer[i]== '\r' && buffer[i+1] == '\n') {
      i += 2;
      break;
    }
    i = getWord (currWord, buffer, i, lSize);
    keepDate = 0;
    if (firstEnddev == NULL) {
      firstEnddev = (enddev *) malloc (sizeof(enddev));
      firstEnddev->next = NULL;
      firstEnddev->new = lastFile ? 1 : 0;
      firstEnddev->old = 0;
      firstEnddev->prev_last_time_seen[0] = '\0';
      strcpy(firstEnddev->last_time_displayed, "0000-00-00 00:00:00");
      firstEnddev->maxPwrLevel = -100;
      firstEnddev->lat = firstEnddev->lon = 0.0;
      bzero(firstEnddev->maxPwrTime, 80);
      lastEnddev = currEnddev = firstEnddev;
      sta_count++;
    } else {
//      currEnddev = findEnddevByMAC (firstEnddev, currWord);
      currEnddev = findStaHT (statable, currWord);
      if (currEnddev == NULL) {
        if (verbosity>=2) printf("Did not find %s lastfile: %d\n", currWord, lastFile);
        currEnddev = (enddev *) malloc (sizeof(enddev));
        currEnddev->next = NULL;
        currEnddev->new = lastFile ? 1 : 0;
        currEnddev->old = 0;
        currEnddev->prev_last_time_seen[0] = '\0';
        strcpy(currEnddev->last_time_displayed, "0000-00-00 00:00:00");
        currEnddev->maxPwrLevel = -100;
        bzero(currEnddev->maxPwrTime, 80);
        currEnddev->lat = currEnddev->lon = 0.0;
        lastEnddev->next = currEnddev;
        lastEnddev = currEnddev;
        sta_count++;
      } else {
        strcpy (first_time_seen, currEnddev->first_time_seen);
        currEnddev->new = 0;
        currEnddev->old = lastFile ? 1 : 0;
        keepDate = 1;
      }
    }
    strcpy (currEnddev->station_mac, currWord);
    memcpy (mac, currEnddev->station_mac, 8);
    mac[8] = '\0';
    strcpy (currEnddev->vendor, findVendorByMACBin (mac_database, mac_db_sz, mac));
    // "Vendor" is actually the description in this case
    strcpy (currEnddev->desc, findVendorByMACBin (known_macs, known_macs_sz, currEnddev->station_mac));
    // Do the same for the IP address
    strcpy (currEnddev->ip, findVendorByMAC (known_ips, currEnddev->station_mac));
    i = getWord (currEnddev->first_time_seen, buffer, i, lSize);
    if (keepDate) strcpy (currEnddev->first_time_seen, first_time_seen);
    i = getWord (currEnddev->last_time_seen, buffer, i, lSize);
    if (!lastFile) strcpy(currEnddev->prev_last_time_seen, currEnddev->last_time_seen);
    i = getWord (power, buffer, i, lSize);
    currEnddev->oldPower = 0;
    if (currEnddev->old) currEnddev->oldPower = currEnddev->power;
    currEnddev->power = atoi(power);
    i = getWord (currEnddev->packets, buffer, i, lSize);
    i = getWord (currEnddev->bssid, buffer, i, lSize);
    if (currEnddev->bssid[0] != '(') { // (not associated)
      currAp = findApHT (aptable, currEnddev->bssid);
      if (currAp != NULL) {
        if (verbosity>=2) printf("Could not find %s\n", currEnddev->bssid);
        strcpy(currEnddev->essid, currAp->essid);
	strcpy(currEnddev->channel, currAp->channel); // also grab the channel
      } else {
        strcpy(currEnddev->essid, "");
        strcpy(currEnddev->channel, "");
      }
    } else {
      strcpy(currEnddev->essid, "");
      strcpy(currEnddev->channel, "");
    }
    strcpy (currEnddev->fileName, fileName);
    memcpy(&(currEnddev->prvtime2), &(currEnddev->time2), sizeof(datetime));
    sscanf (currEnddev->first_time_seen, "%d-%d-%d %d:%d:%d",
      &(currEnddev->time1.year),
      &(currEnddev->time1.month),
      &(currEnddev->time1.day),
      &(currEnddev->time1.hour),
      &(currEnddev->time1.minute),
      &(currEnddev->time1.second));
    sscanf (currEnddev->last_time_seen, "%d-%d-%d %d:%d:%d",
      &(currEnddev->time2.year),
      &(currEnddev->time2.month),
      &(currEnddev->time2.day),
      &(currEnddev->time2.hour),
      &(currEnddev->time2.minute),
      &(currEnddev->time2.second));
    if (currEnddev->power > currEnddev->maxPwrLevel && currEnddev->power < -1) {
      currEnddev->maxPwrLevel = currEnddev->power;
      strcpy(currEnddev->maxPwrTime, currEnddev->last_time_seen);
    }
    if (strcmp(currEnddev->maxPwrTime, "") == 0) strcpy(currEnddev->maxPwrTime, currEnddev->last_time_seen);
    // Skip leading whitespace
    while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

    // Grab the whole list of ESSIDs
    j = 0;
    while (i < lSize-1 && j < 253) {
      if (buffer[i] == '\r' && buffer[i+1] == '\n') {
        i += 2;
        break;
      }
      if (buffer[i] == '\n') {
        i++;
        break;
      }
      currEnddev->probed_essids[j] = buffer[i];
      i++; j++;
    }
    currEnddev->probed_essids[j] = '\0';
    if (findStaHT (statable, currEnddev->station_mac) == NULL) addStaToHT(statable, currEnddev);
    if (verbosity>=2) printf("added sta (new? %d): %s\n", currEnddev->new, currEnddev->station_mac);
  }

//  fclose(pFile);
  free (buffer);

  if (verbosity>=2) printf("Finished reading %s\n", fileName);  // Debug
  dset.s = firstAp;
  dset.e = firstEnddev;
  return dset;
}

int main (int argc, char **argv) {
  int i, lastFile, showAPs, showEnddevs;
  ap *firstAp = NULL;
  enddev *firstEnddev = NULL;
  gps *gps1 = NULL;
  devset dset;
/*
  FILE *csvFile = NULL;
  FILE *textFile = NULL;
  FILE *htmlFile = NULL;
 */
  FILE *tmpFile = NULL;
  char *fileToMonitor = NULL;
  char *filePrefix = NULL;
  char *gpsFile = NULL;
  char buffer[256];
//  int continuous = 0; //boolean

  // Set the default values
  onlyAddCommon = 0;
  onlyAddNew = 0;
  onlyAddOld = 0;
  deltaSpecified = 0;
  numInputFiles = 0;
  showAPs = 1;
  showEnddevs = 1;
  minPower = -100;
  maxPower = 0;
  minPowerDelta = -1;
  text_brief = 0;
  verbosity = 0;
  ap_count = 0;
  sta_count = 0;
  timeMin = 0;
  timeMax = 0;
  remoteserver = NULL;
  extraStaCt = 0;
  collisions = 0;
  kmlFile = NULL; // 2018-03-24

  if (argc < 2) {
    printf ("Usage: %s [options] -w prefix file1 [file2] [file3]...[-l] [file n]\n", argv[0]);
    printf ("-a only show APs\n");
    printf ("-b print brief text in text mode\n");
    printf ("-e only show end devices\n");
//    printf ("-c specifies a csv file to output to\n");
//    printf ("-t specifies a text file to output to\n");
    printf ("-to prints text to stdout (cannot be used with -t)\n");
//    printf ("-h specifies a html file to output to\n");
    printf ("-g [file] specifies a GPS input file\n");
    printf ("-i [file] specifies a CSV file of known IP addresses\n");
    printf ("-l specifies the last file (must be the last file specified)\n");
    printf ("-k [file] specifies a CSV file of known MAC addresses\n");
    printf ("-m only show APs and Stations in the file specified with -k\n");
    printf ("-d [delta] only shows devices whose power is stronger than before by [delta]\n");
    printf ("-n only shows APs and Stations that are new in the last file\n");
    printf ("-o only shows APs and Stations that are not new in the last file\n");
    printf ("-p [power] only shows APs and Stations with power greater than [power]\n");
    printf ("-P [power] only shows APs and Stations with power less than [power]\n");
    printf ("-sl sort by last time seen\n");
    printf ("-t only shows APs and Stations greater than the minimum time\n");
    printf ("-T only shows APs and Stations less than the maximum time\n");
    printf ("-u [server] [port] send findings to UDP server on [server]:[port]\n");
    printf ("-v verbose output\n");
    printf ("-vv very verbose output\n");
    printf ("-w [prefix] specifies output file prefix\n");
    return 1;
  }

  firstAp = NULL;
  firstEnddev = NULL;

  tmpFile = fopen("/usr/share/aircrack-ng/airodump-ng-oui.txt", "r");
  if (tmpFile) {
    fclose(tmpFile);
    readMacDB ("/usr/share/aircrack-ng/airodump-ng-oui.txt");
//    printf("reading /usr/share/aircrack-ng/airodump-ng-oui.txt\n");
  } else if (tmpFile = fopen("/etc/aircrack-ng/airodump-ng-oui.txt", "r")) {
    fclose(tmpFile);
    readMacDB ("/etc/aircrack-ng/airodump-ng-oui.txt");
//    printf("reading /etc/aircrack-ng/airodump-ng-oui.txt\n");
  } 
  for (i = 1; i < argc; i++) {
/*
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-C") == 0) {
      i++;
      if (i >= argc) {
        printf ("-c requires that you specify an output csv file.\n");
        exit(1);
      }
      csvFile = fopen(argv[i], "w");
      if (csvFile == NULL) {
        printf ("Error opening CSV file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
/*
    if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "-T") == 0) {
      i++;
      if (i >= argc) {
        printf ("-t requires that you specify an output text file.\n");
        exit(1);
      }
      textFile = fopen(argv[i], "w");
      if (textFile == NULL) {
        printf ("Error opening text file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
    if (strcmp(argv[i], "-to") == 0 || strcmp(argv[i], "-TO") == 0) {
      if (textFile != NULL) {
        fprintf (stderr, "Error: -to cannot be used with -t\n");
        exit(1);
      }
      textFile = stdout;
      continue;
    }
/*
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0) {
      i++;
      if (i >= argc) {
        printf ("-h requires that you specify an output text file.\n");
        exit(1);
      }
      htmlFile = fopen(argv[i], "w");
      if (htmlFile == NULL) {
        printf ("Error opening html file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
    if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-A") == 0) {
      showEnddevs = 0;
      continue;
    }
    if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "-B") == 0) {
      text_brief = 1;
      continue;
    }
    if (strcmp(argv[i], "-d") == 0) {
      i++;
      if (i >= argc) {
        printf ("-d requires that you specify a minimum delta power level.\n");
        exit(1);
      }
      deltaSpecified = 1;
      minPowerDelta = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-E") == 0) {
      showAPs = 0;
      continue;
    }
    if (strcmp(argv[i], "-g") == 0) {
      i++;
      if (i >= argc) {
        printf ("-g requires that you specify a GPS file.\n");
        continue;
      }
      gpsFile = argv[i];
      continue;
    }
    if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) {
      i++;
      if (i >= argc) {
        printf ("-i requires that you specify a MAC/IP address file.\n");
        exit(1);
      }
      readKnownIPs(argv[i]);

      continue;
    }
    if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "-K") == 0) {
      i++;
      if (i >= argc) {
        printf ("-k requires that you specify a MAC address/hostname file.\n");
        exit(1);
      }
      if (verbosity) printf ("Reading known MACs.\n");
      readKnownMacs(argv[i]);

      continue;
    }
    if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-M") == 0) {
      onlyShowKnown = 1;
      continue;
    }
    if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "-N") == 0) {
      onlyAddNew = 1;
      continue;
    }
    if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "-O") == 0) {
      onlyAddOld = 1;
      continue;
    }
    if (strcmp(argv[i], "-p") == 0) {
      i++;
      if (i >= argc) {
        printf ("-p requires that you specify a minimum power level.\n");
        exit(1);
      }
      minPower = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-P") == 0) {
      i++;
      if (i >= argc) {
        printf ("-P requires that you specify a maximum power level.\n");
        exit(1);
      }
      maxPower = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-t") == 0) {
      timeMin = 1;
      continue;
    }
    if (strcmp(argv[i], "-T") == 0) {
      timeMax = 1;
      continue;
    }
    if (strcmp(argv[i], "-sf") == 0) {
      sortBy = FIRSTSEEN;
      continue;
    }
    if (strcmp(argv[i], "-sl") == 0) {
      sortBy = LASTSEEN;
      continue;
    }
    if (strcmp(argv[i], "-u") == 0) {
      i++;
      if (i+1 >= argc) {
        printf ("-u requires that you specify a server and port");
        exit(1);
      }
      remoteserver = argv[i];
      i++;
      remoteport = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-v") == 0) {
      verbosity = 1;
      continue;
    }
    if (strcmp(argv[i], "-vv") == 0) {
      verbosity = 2;
      continue;
    }
    if (strcmp(argv[i], "-w") == 0) {
      i++;
      if (i >= argc) {
        printf ("-w requires that you specify an output prefix.\n");
        continue;
      }
      filePrefix = argv[i];
      continue;
    }
    // Note the lack of a continue statement after -l - this option must be last
    lastFile = 0;
    if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-L") == 0) {
      lastFile = 1;
      i++;
      if (i >= argc) {
        printf ("-l requires that you specify an input csv file.\n");
        exit(1);
      }
      fileToMonitor = argv[i];
    }
    if (verbosity) printf ("Reading CSV file: %s\n", argv[i]);
    dset = readCSVFile (argv[i], firstAp, firstEnddev, lastFile);
    firstAp = dset.s;
    firstEnddev = dset.e;
    numInputFiles++;
    if (verbosity >= 2) printf ("Finished reading CSV file.\n");
  }

  // Check for show stoppers
  if (numInputFiles == 0) {
    fprintf (stderr, "Error: no input files specified.\n");
    exit(1);
  }
  if (filePrefix == NULL) {
    printf ("Please specify an output prefix (-w option).\n");
    exit(1);
  }

  // Debug pointer
  firstEnddevDbg = firstEnddev;
  // Print the power level files
  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-appower.csv");
  if (verbosity) printf ("Opening file: %s\n", buffer);
  tmpFile = fopen(buffer, "r");
  if (tmpFile) {
    readAPPowerFromFile (firstAp, tmpFile);
    fclose (tmpFile);
  }
  tmpFile = fopen(buffer, "w");
  printAPPowerToFileRec (firstAp, tmpFile);
  if (verbosity >= 2) printf("printAPPowerToFileRec done\n");
  fclose(tmpFile);

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-stapower.csv");
  if (verbosity) printf ("Opening file: %s\n", buffer);
  tmpFile = fopen(buffer, "r");
  if (tmpFile) {
    readEnddevPowerFromFile (firstEnddev, tmpFile);
    fclose (tmpFile);
  }
  tmpFile = fopen(buffer, "w");
  printEndDevicesPowerToFileRec (firstEnddev, tmpFile);
  fclose(tmpFile);

  if (gpsFile) tmpFile = fopen(gpsFile, "r");
  if (gpsFile && tmpFile) {
    if (verbosity) printf ("Opening file: %s\n", gpsFile);
    gps1 = readGPSFile(firstAp, firstEnddev, tmpFile);
    addGPSInfo (firstAp, firstEnddev, gps1);
    free_gps(gps1);
  }

  // read last time displayed
  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-printed.csv");
  if (verbosity) printf ("Opening file: %s\n", buffer);
  tmpFile = fopen(buffer, "r");
  if (tmpFile) {
    readEnddevDisplayedFromFile (firstEnddev, tmpFile);
    fclose (tmpFile);
  }

//  csvFile = htmlFile = kmlFile = NULL;

  if (textFile != stdout) {
    strcpy (buffer, "");
    strcat (buffer, filePrefix);
    strcat (buffer, ".txt");
    if (verbosity) printf ("Opening %s\n", buffer);
    textFile = fopen(buffer, "w");
  }

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, ".csv");
  if (verbosity) printf ("Opening %s\n", buffer);
  csvFile = fopen(buffer, "w");

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, ".html");
  if (verbosity) printf ("Opening %s\n", buffer);
  htmlFile = fopen(buffer, "w");

  if (gpsFile) {
    strcpy (buffer, "");
    strcat (buffer, filePrefix);
    strcat (buffer, ".kml");
    if (verbosity) printf ("Opening %s\n", buffer);
    kmlFile = fopen (buffer, "w");
  }

/*
  if (textFile != NULL) {
    if (showAPs) printAPsToFileText (firstAp, textFile);
    if (showEnddevs) printEndDevicesToFileText (firstEnddev, textFile);
    if (textFile != stdout) fclose (textFile);
  }
*/

  if (csvFile && htmlFile && textFile) {
    if (gpsFile) {
      fprintf (kmlFile, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\r\n<Document>\r\n");
    }
    if (showAPs) {
      fprintf (csvFile, "%sBSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
      "Power, # beacons, # IV, LAN IP, ID-Length, ESSID, Key%s", CRLF, CRLF);
      fprintf (htmlFile, "<html>%s<head></head><body>%s<table border=\"1\">%s", CRLF, CRLF, CRLF);
      fprintf (htmlFile, "<tr><td>BSSID</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Prev time seen</td><td>channel</td><td>Speed</td><td>Privacy</td><td>Cipher</td><td>Authentication</td>"
        "<td>Power</td><td># beacons</td><td># IV</td><td>LAN IP</td><td>ID-Length</td><td>ESSID</td><td>Key</td><td>Description</td><td>IP Address</td></tr>%s", CRLF);

      if (verbosity) printf ("Printing APs to files\n");
      printAPsToFileRec (firstAp);
    }
    if (showEnddevs) {
      fprintf (csvFile, "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs%s", CRLF);
      fprintf (htmlFile, "</table><table border=\"1\"><tr><td>Station MAC</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Previous time seen</td><td>Power</td>"
        "<td># packets</td><td>BSSID</td><td>channel</td><td>ESSID</td><td>Probes</td><td>Description</td><td>IP Address</td></tr>%s", CRLF);
      if (verbosity) printf ("Printing Stations to files\n");
      printEndDevicesToFileRec (firstEnddev);
    }
    fprintf (htmlFile, "</table>%s</body>%s</html>", CRLF, CRLF);
    if (verbosity >= 2) printf("Done printing regular files\n");
    if (gpsFile) {
      if (verbosity >= 2) printf("Closing KML file\n");
      fprintf (kmlFile, "</Document>\r\n</kml>\r\n");
      fclose (kmlFile);
    }
/*
    fclose (csvFile);
    fclose (htmlFile);
    fclose (textFile);
*/
    if (verbosity) printf ("Closed files\n");
  }

  // write last time displayed
  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-printed.csv");
  if (verbosity) printf ("Opening file for writing: %s\n", buffer);
  tmpFile = fopen(buffer, "w");
  if (tmpFile) {
    printEndDevicesDisplayedToFile (firstEnddev, tmpFile);
    fclose(tmpFile);
  } else {
    fprintf (stderr, "Error opening %s\n", buffer);
    perror("main");
  }

/*
  if (htmlFile != NULL) {
    if (showAPs) {
      fprintf (htmlFile, "<html>%s<head></head><body>%s<table border=\"1\">%s", CRLF, CRLF, CRLF);
      fprintf (htmlFile, "<tr><td>BSSID</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>channel</td><td>Speed</td><td>Privacy</td><td>Cipher</td><td>Authentication</td>", CRLF);
      fprintf (htmlFile, "<td>Power</td><td># beacons</td><td># IV</td><td>LAN IP</td><td>ID-Length</td><td>ESSID</td><td>Key</td></tr>%s", CRLF);
      printAPsToFileHTML (firstAp, htmlFile);
      fprintf (htmlFile, "</table>%s", CRLF);
    }
    if (showEnddevs) {
      fprintf (htmlFile, "<table border=\"1\">%s", CRLF);
      fprintf (htmlFile, "<tr><td>Station MAC</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Power</td><td># packets</td><td>BSSID</td><td>ESSID</td><td>Probes</td></tr>%s", CRLF);
      printEndDevicesToFileHTML (firstEnddev, htmlFile);
      fprintf (htmlFile, "</table>%s</body>%s</html>", CRLF, CRLF, CRLF);
    }
    fclose (htmlFile);
  }
*/
/*
  if (continuous && fileToMonitor == NULL) {
    printf ("Error, last file not specified.\n");
    return 1;
  }
  while (continuous) {
    dset = readCSVFile (fileToMonitor, firstAp, firstEnddev, lastFile);
    firstAp = dset.s;
    firstEnddev = dset.e;
    if (showAPs) printAPsToFileText (firstAp, stdout);
    if (showEnddevs) printEndDevicesToFileText (firstEnddev, stdout);
    sleep(3);
  }
*/
//  printf("Collisions: %d\n", collisions);
  if (verbosity) printf ("Freeing up memory\n");
  free_ap(firstAp);
  free_enddev(firstEnddev);
  free(known_macs);
  if (mac_db_sz > 0)
    free(mac_database);
  free_ht_ap (aptable);
  free_ht_sta (statable);
  if (verbosity) printf ("Program terminated\n");
  return 0;
}

